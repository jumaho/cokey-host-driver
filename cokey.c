/*
 * CoKey host driver:
 * Driver to integrate a CoKey USB device into a Linux host's crypto API.
 *
 * Copyright (c) 2015-2016, Fraunhofer AISEC.
 * Author: Julian Horsch <julian.horsch@aisec.fraunhofer.de>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */


/*
 * Long-term TODOs:
 *  - Adapt to new skcipher Linux crypto API
 *  - Implement handling of multiple CoKey devices/interfaces on the same system
 *  - Include the CoKey device serial number into algorithm name provided on the host
 *  - Handle CoKey device disconnects when in use gracefully
 *  - Set proper protocol tags, receive and check them
 *  - Find proper USB vendor/interface class IDs
 */

#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/kref.h>
#include <linux/uaccess.h>
#include <linux/usb.h>
#include <linux/mutex.h>
#include <linux/hrtimer.h>
#include <linux/ktime.h>

/* Crypto API stuff */
#include <linux/crypto.h>
#include <crypto/algapi.h>
#include <crypto/aes.h>


/* Define these values to match your devices */
#define USB_COKEY_VENDOR_ID	0x1d6b
//#define USB_COKEY_PRODUCT_ID	0xfff0
#define USB_COKEY_INTERFACE_CLASS 0xff
#define USB_COKEY_INTERFACE_SUBCLASS 0xab
#define USB_COKEY_INTERFACE_PROTOCOL 0xcd

//#define COKEY_MIN_USB_PACKET_LENGTH 0x8000
//#define COKEY_MIN_USB_PACKET_LENGTH_FAST 0x2000

/* TODO synchronize access to module parameters */
static int cokey_usb_packet_length = 0x8000;
static int cokey_usb_packet_length_fast = 0x3000;
static int cokey_usb_packet_short_retries = 1800;

module_param(cokey_usb_packet_length, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(cokey_usb_packet_length, "Desired USB packet length for aesusbproxy");
module_param(cokey_usb_packet_length_fast, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(cokey_usb_packet_length_fast, "Desired USB packet length for aesusb");
module_param(cokey_usb_packet_short_retries, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(cokey_usb_packet_short_retries, "Times of tasklet rescheduling for short USB packets");

#define COKEY_RESPONSE_CONTAINER

#define CRYPTO_QUEUE_LEN 0x100000

/* table of devices that work with this driver */
static const struct usb_device_id cokey_table[] = {
	{ USB_VENDOR_AND_INTERFACE_INFO(USB_COKEY_VENDOR_ID,
			USB_COKEY_INTERFACE_CLASS,
			USB_COKEY_INTERFACE_SUBCLASS,
			USB_COKEY_INTERFACE_PROTOCOL) },
	{ }					/* Terminating entry */
};
MODULE_DEVICE_TABLE(usb, cokey_table);

/***********************************************/
/* cokey USB protocol */
enum cokey_command_code {
        COKEY_CMD_SETKEY,
        COKEY_CMD_CTR_ENCRYPT,
        COKEY_CMD_CTR_DECRYPT,
        COKEY_CMD_ECB_ENCRYPT,
        COKEY_CMD_ECB_DECRYPT,
        COKEY_CMD_SETALG,
        COKEY_CMD_GETALG,
	COKEY_CMD_CONTAINER,
	COKEY_CMD_CONTAINER_RESP_CONTAINER,
};

enum cokey_status_code {
        COKEY_STATUS_OK,
        COKEY_STATUS_ERROR,
};

#define COKEY_COMMAND_LENGTH (3*4)
#define COKEY_STATUS_LENGTH (2*4)

struct cokey_command {
        enum cokey_command_code code;
        uint32_t length;
        uint32_t tag;
};

struct cokey_status {
        enum cokey_status_code code;
        uint32_t tag;
};

typedef struct {
        struct work_struct my_work;
	struct urb *urb;
} cokey_work_urb_t;

struct cokey_reqctx {
	int cmd_code;
//	uint32_t tag;
};

struct req_list_entry {
	struct list_head list;
	struct ablkcipher_request *req;
	unsigned int response_length;
	int cmd_code;
};

/* bool fast_mode determines if a testing proxy mode is used or the normal CoKey
 * "fast_mode" */
struct cokey_in_urb_context {
	struct cokey_dev *dev;
	struct ablkcipher_request *req;
	struct list_head *req_list;
	bool fast_mode;
};

/* TODO if we want to support multiple usbarmorys attached to a single host:
 *  - dynamically create a crypto_alg name and structure for each attached
 * usbarmory
 *  - when receiving crypto requests, determine which usbarmory is involved by
 *  reading the name of the tfm and act accordingly */
static struct cokey_dev *cokey_device;

struct cokey_tfm_ctx {
	/* Each transformation is associated with exactly one cokey device */
	struct cokey_dev *dev;

	/* Each transformation has a key */
	uint8_t                     aes_key[AES_MAX_KEY_SIZE];
	int                         keylen;

	bool fast_mode; // this is set depending on which algo is allocated

	/* crypto api cipher to be used on the host for fast mode */
	struct crypto_ablkcipher *fast_cipher;
};

/* Structure to hold all of our usb device specific data */
struct cokey_dev {
	struct usb_device	*udev;			/* the usb device for this device */
	struct usb_interface	*interface;		/* the interface for this device */
	struct usb_anchor	submitted;		/* in case we need to retract our submissions */
	struct kref		kref;
	spinlock_t		lock;
	__u8			bulk_in_endpointAddr;	/* the address of the bulk in endpoint */
	__u8			bulk_out_endpointAddr;	/* the address of the bulk out endpoint */

	//struct mutex		io_mutex;		/* synchronize I/O with disconnect */

	struct urb		*current_out_urb;
	struct list_head	*current_req_list;
	bool			urb_is_cmd_container;
	bool			urb_is_fast_mode;
	int already_tried;
	struct hrtimer timer;

	struct workqueue_struct *wq_urb;
	struct tasklet_struct       tasklet;

	/* Crypto API stuff */
	struct crypto_queue         queue;
	struct cokey_tfm_ctx *active_tfm_ctx;

};
#define to_cokey_dev(d) container_of(d, struct cokey_dev, kref)

static struct usb_driver cokey_driver;

static void cokey_delete(struct kref *kref)
{
	struct cokey_dev *dev = to_cokey_dev(kref);

	flush_workqueue(dev->wq_urb);
	destroy_workqueue(dev->wq_urb);

	tasklet_kill(&dev->tasklet);

	usb_put_dev(dev->udev);
	kfree(dev);
}

/* This function is called when a crypto API user calls crypto_alloc_cipher()
 * for ctr(aesusbproxy) */
static int cokey_cra_init(struct crypto_tfm *tfm)
{
	struct cokey_tfm_ctx *ctx = crypto_tfm_ctx(tfm);

	pr_debug("%s enter\n", __func__);

	/* set request context size if we need context for each request */
	tfm->crt_ablkcipher.reqsize = sizeof(struct cokey_reqctx);

	ctx->fast_mode = false;
	ctx->fast_cipher = NULL;

	return 0;
}

/* This function is called when a crypto API user calls crypto_alloc_cipher()
 * for ctr(aesusb) */
static int cokey_cra_fast_init(struct crypto_tfm *tfm)
{
	//const char *name = crypto_tfm_alg_name(tfm);
	struct cokey_tfm_ctx *ctx = crypto_tfm_ctx(tfm);

	pr_debug("%s enter\n", __func__);

	/* set request context size if we need context for each request */
	tfm->crt_ablkcipher.reqsize = sizeof(struct cokey_reqctx);

	ctx->fast_mode = true;
	ctx->fast_cipher = crypto_alloc_ablkcipher("ctr(aes)", 0, 0);
			//CRYPTO_ALG_ASYNC | CRYPTO_ALG_NEED_FALLBACK);
	if (IS_ERR(ctx->fast_cipher)) {
		pr_err("Error allocating cipher for fast mode\n");
		return PTR_ERR(ctx->fast_cipher);
	}

	return 0;
}

static void cokey_cra_exit(struct crypto_tfm *tfm)
{
	struct cokey_tfm_ctx *ctx = crypto_tfm_ctx(tfm);
	pr_debug("%s enter\n", __func__);

	if (ctx->fast_cipher) {
		crypto_free_ablkcipher(ctx->fast_cipher);
	}
	ctx->fast_cipher = NULL;
}

static int cokey_setkey(struct crypto_ablkcipher *cipher, const uint8_t *key, unsigned int keylen)
{
	struct crypto_tfm  *tfm = crypto_ablkcipher_tfm(cipher);
	struct cokey_tfm_ctx *ctx = crypto_tfm_ctx(tfm);
	int ret = 0;

	pr_debug("%s enter\n", __func__);

	if (!ctx->fast_mode &&
	    keylen != AES_KEYSIZE_128 &&
	    keylen != AES_KEYSIZE_192 &&
	    keylen != AES_KEYSIZE_256)
		return -EINVAL;

	memcpy(ctx->aes_key, key, keylen);
	ctx->keylen = keylen;

	if (ctx->fast_mode) {
		pr_debug("%s: setting key in fast host cipher\n", __func__);
		ctx->fast_cipher->base.crt_flags &= ~CRYPTO_TFM_REQ_MASK;
		ctx->fast_cipher->base.crt_flags |=
			(cipher->base.crt_flags & CRYPTO_TFM_REQ_MASK);

		ret = crypto_ablkcipher_setkey(ctx->fast_cipher, key, keylen);
		if (ret) {
			tfm->crt_flags &= ~CRYPTO_TFM_RES_MASK;
			tfm->crt_flags |=
				(ctx->fast_cipher->base.crt_flags & CRYPTO_TFM_RES_MASK);
		}
	}

	pr_debug("%s exit", __func__);
	return ret;
}

static void cokey_cleanup_req_list(struct list_head *req_list, int error)
{
	struct req_list_entry *entry, *next;

	pr_debug("%s entered\n", __func__);

	if (!req_list) {
		return;
	}

	if (!list_empty(req_list)) {
		list_for_each_entry_safe(entry, next, req_list, list) {
			entry->req->base.complete(&entry->req->base, error);
			// remove and free the list entry
			list_del(&entry->list);
			kfree(entry);
		}
	}
	kfree(req_list);
}

static void cokey_fill_buf_from_cmd(void *buf, struct cokey_command *cmd)
{
	*(uint32_t *)(buf) = cpu_to_le32(cmd->code);
	*(uint32_t *)(buf+4) = cpu_to_le32(cmd->length);
	*(uint32_t *)(buf+8) = cpu_to_le32(cmd->tag);
}

static struct cokey_dev *cokey_get_dev_from_tfm(struct crypto_ablkcipher *tfm)
{
	// TODO implement multi-usb-device-handling
	return cokey_device;
}

static void cokey_urb_complete_out_cb(struct urb *urb)
{
	struct cokey_dev *dev = urb->context;

	pr_debug("%s entered\n", __func__);

	if (urb->status) {
		if (!(urb->status == -ENOENT
					|| urb->status == -ECONNRESET
					|| urb->status == -ESHUTDOWN))
			dev_err(&dev->interface->dev, "%s - nonzero write bulk status received: %d\n", __func__, urb->status);
	}

	usb_free_urb(urb);
}

static void cokey_handle_request_fast_mode(struct ablkcipher_request *req, int cmd_code, void *response_buf, void *response_buf_end)
{
	struct crypto_ablkcipher   *tfm    = crypto_ablkcipher_reqtfm(req);
	struct cokey_tfm_ctx         *ctx    = crypto_ablkcipher_ctx(tfm);

	int error = 0;

	//pr_debug("%s entered\n", __func__);
	/* first check if the request can be satisfied, i.e. is there
	 * enough data? */
	if (response_buf + AES_BLOCK_SIZE > response_buf_end) {
		pr_err("%s: Not enough data to handle request\n", __func__);
		error = -EFAULT;
		goto out;
	}

	/* copy encrypted IV to req->info */
	memcpy(req->info, response_buf, AES_BLOCK_SIZE);

	ablkcipher_request_set_tfm(req, ctx->fast_cipher);
	if (cmd_code == COKEY_CMD_CTR_ENCRYPT) {
		error = crypto_ablkcipher_encrypt(req);
	} else if (cmd_code == COKEY_CMD_CTR_DECRYPT) {
		error = crypto_ablkcipher_decrypt(req);
	} else {
		pr_err("unsupported command for cokey fast mode\n");
		error = -EFAULT;
	}
	pr_debug("%s: request to fast host cipher returned with %d\n", __func__, error);
	ablkcipher_request_set_tfm(req, tfm);
out:
	req->base.complete(&req->base, error);
}

static void cokey_handle_request(struct ablkcipher_request *req, void *response_buf, void *response_buf_end)
{
	int retval, error = 0;

	//pr_debug("%s entered\n", __func__);

	/* first check if the request can be satisfied, i.e. is there
	 * enough data? */
	if (response_buf + AES_BLOCK_SIZE + req->nbytes >
			response_buf_end) {
		pr_err("%s: Not enough data to handle request\n", __func__);
		error = -EFAULT;
		goto out;
	}

	/* copy result iv */
	// TODO is this necessary?
	memcpy(req->info, response_buf, AES_BLOCK_SIZE);

	/* copy result data */
	retval = sg_copy_from_buffer(req->dst, sg_nents(req->dst), response_buf+AES_BLOCK_SIZE, req->nbytes);
	if (retval != req->nbytes) {
		pr_err("could only copy %d/%d bytes to destination scatterlist\n", retval, req->nbytes);
		error = -EFAULT;
	}

out:
	req->base.complete(&req->base, error);
}

static void cokey_wq_incoming_urb(struct work_struct *work)
{
	cokey_work_urb_t *cokey_work = (cokey_work_urb_t *)work;
	struct urb *urb = cokey_work->urb;
	struct cokey_in_urb_context *ctx = urb->context;

	struct req_list_entry *entry, *next;
	void *urb_transfer_buffer_end = urb->transfer_buffer +
		urb->transfer_buffer_length;
	void *curr_urb_buf;

	if (ctx->req_list) {
		/* Iterate over all requests included in this response */
		curr_urb_buf = urb->transfer_buffer;

		list_for_each_entry_safe(entry, next, ctx->req_list, list) {
			if (ctx->fast_mode) {
				cokey_handle_request_fast_mode(entry->req, entry->cmd_code, curr_urb_buf,
						urb_transfer_buffer_end);
			} else {
				cokey_handle_request(entry->req, curr_urb_buf,
						urb_transfer_buffer_end);
			}

			/* increment buffer pointer */
			curr_urb_buf += entry->response_length;

			/* remove and free the list entry */
			list_del(&entry->list);
			kfree(entry);
		}
		/* list should be empty by now => free the list head */
		kfree(ctx->req_list);
	} else if (ctx->req) {
		/* only a single request is included within this response */
		cokey_handle_request(urb->context, urb->transfer_buffer,
				urb_transfer_buffer_end);
	} else {
		pr_err("%s - invalid urb context structure", __func__);
	}

	kfree(ctx);
	/* freeing the urb should also free the buffer (URB_FREE_BUFFER) */
	usb_free_urb(urb);
	kfree(work);
}

static void cokey_urb_complete_in_cb(struct urb *urb)
{
	struct cokey_in_urb_context *ctx = urb->context;
	cokey_work_urb_t *work;

	int err = 0;

	pr_debug("%s entered\n", __func__);

	if (urb->status) {
		if (!(urb->status == -ENOENT
					|| urb->status == -ECONNRESET
					|| urb->status == -ESHUTDOWN))
			pr_err("%s - nonzero read bulk status received: %d\n", __func__, urb->status);
	}

	if (!ctx) {
		usb_free_urb(urb);
		return;
	}

	/* init work item */
	work = kmalloc(sizeof(cokey_work_urb_t), GFP_ATOMIC);
	if (!work) {
		pr_err("Could not allocate work struct\n");
		err = -ENOMEM;
		goto error;
	}
	work->urb = urb;
	/* enqueue work */
	INIT_WORK((struct work_struct *)work, cokey_wq_incoming_urb);
	queue_work(ctx->dev->wq_urb, (struct work_struct *)work);

	return;
error:
	if (ctx && ctx->req_list) {
		cokey_cleanup_req_list(ctx->req_list, err);
	} else if (ctx && ctx->req) {
		ctx->req->base.complete(&ctx->req->base, err);
	}

	usb_free_urb(urb);
}

static int cokey_send_command_urb(struct cokey_dev *dev, struct
		cokey_command *cmd)
{
	struct urb *urb;
	void *buf = NULL;
	int retval = 0;

	pr_debug("%s entered\n", __func__);

	urb = usb_alloc_urb(0, GFP_KERNEL);

//	buf = usb_alloc_coherent(dev->udev, COKEY_COMMAND_LENGTH,
//			GFP_KERNEL, &urb->transfer_dma);

	buf = kmalloc(COKEY_COMMAND_LENGTH, GFP_KERNEL);
	if (!buf) {
		retval = -ENOMEM;
		goto error;
	}

	cokey_fill_buf_from_cmd(buf, cmd);

	usb_fill_bulk_urb(urb, dev->udev,
			usb_sndbulkpipe(dev->udev, dev->bulk_out_endpointAddr),
			buf, COKEY_COMMAND_LENGTH,
			cokey_urb_complete_out_cb, dev);

	//urb->transfer_flags |= URB_NO_TRANSFER_DMA_MAP;
	urb->transfer_flags |= URB_FREE_BUFFER;

	usb_anchor_urb(urb, &dev->submitted);

	retval = usb_submit_urb(urb, GFP_KERNEL);

	if (retval) {
		dev_err(&dev->interface->dev,
			"%s - failed submitting write urb, error %d\n",
			__func__, retval);
		goto error_unanchor;
	}

	pr_debug("%s: submitted command urb code: %d, length: %d\n", __func__,
			cmd->code, cmd->length);

	return 0;

error_unanchor:
	usb_unanchor_urb(urb);
error:
	if (urb) {
		//usb_free_coherent(dev->udev, sizeof(struct cokey_command), buf, urb->transfer_dma);
		usb_free_urb(urb);
	}

	return retval;
}

/* don't ask questions, simply send the current urb */
static int cokey_cmd_finish(struct cokey_dev *dev)
{
	struct cokey_command cmd;
	int retval = 0;
	struct urb *urb;
	struct req_list_entry *entry, *next;
	void *buf;

	unsigned int response_length = 0;
	struct cokey_in_urb_context *ctx = NULL;

	pr_debug("%s enter\n", __func__);

	if (!dev->current_out_urb) {
		return 0;
	}

	if (dev->urb_is_cmd_container || dev->urb_is_fast_mode) {
		// prepare and send enclosing command
		if (dev->urb_is_fast_mode) {
			cmd.code = COKEY_CMD_ECB_ENCRYPT;
			response_length = dev->current_out_urb->transfer_buffer_length;
		} else if (dev->urb_is_cmd_container) {
#ifdef cokey_RESPONSE_CONTAINER
			cmd.code = COKEY_CMD_CONTAINER_RESP_CONTAINER;
#else
			cmd.code = COKEY_CMD_CONTAINER;
#endif
		}

		cmd.length = dev->current_out_urb->transfer_buffer_length;
		cmd.tag = 0; //get_random_int(); // TODO USB Protocol Extension

		if (cokey_send_command_urb(dev, &cmd)) {
			return -1;
		}
	}

	/* send dev->current_out_urb */
	urb = dev->current_out_urb;
	usb_anchor_urb(urb, &dev->submitted);
	retval = usb_submit_urb(urb, GFP_KERNEL);
	if (retval) {
		dev_err(&dev->interface->dev,
			"%s - failed submitting write urb, error %d\n",
			__func__, retval);
		return retval;
	}
	dev->current_out_urb = NULL;

	/************/
	/* RESPONSE */

	/* No response requested? */
	if (!dev->current_req_list) {
		pr_debug("%s: no response requested\n", __func__);
		return 0;
	}

	// TODO refactor this... much code duplication
	if (dev->urb_is_fast_mode) {
		buf = kmalloc(response_length, GFP_KERNEL);
		if (!buf) {
			return -ENOMEM;
		}
		ctx = kmalloc(sizeof(struct cokey_in_urb_context),
				GFP_KERNEL);
		if (!ctx) {
			return -ENOMEM;
		}
		ctx->dev = dev;
		ctx->req = NULL;
		ctx->req_list = dev->current_req_list;
		ctx->fast_mode = true;
		urb = usb_alloc_urb(0, GFP_KERNEL);
		usb_fill_bulk_urb(urb, dev->udev,
				usb_rcvbulkpipe(dev->udev, dev->bulk_in_endpointAddr),
				buf, response_length,
				cokey_urb_complete_in_cb, ctx);
		urb->transfer_flags |= URB_FREE_BUFFER;
		usb_anchor_urb(urb, &dev->submitted);
		retval = usb_submit_urb(urb, GFP_KERNEL);
		if (retval) {
			goto error_submit;
		}
		pr_debug("%s: fast mode, response with length %d requested\n", __func__, response_length);
		dev->current_req_list = NULL;
		return 0;
	}
#ifdef COKEY_RESPONSE_CONTAINER
	list_for_each_entry_safe(entry, next, dev->current_req_list, list) {
		response_length += entry->response_length;
		if (entry->response_length == 0) {
			/* remove requests without response from list */
			list_del(&entry->list);
			kfree(entry);
		}
	}
	if (response_length == 0) {
		/* does not make any sense, so it should not happen */
		pr_debug("Request list with zero response length...\n");
		return 0;
	}
	buf = kmalloc(response_length, GFP_KERNEL);
	if (!buf) {
		return -ENOMEM;
	}
	ctx = kmalloc(sizeof(struct cokey_in_urb_context), GFP_KERNEL);
	if (!ctx) {
		return -ENOMEM;
	}
	ctx->dev = dev;
	ctx->req = NULL;
	ctx->req_list = dev->current_req_list;
	ctx->fast_mode = false;
	urb = usb_alloc_urb(0, GFP_KERNEL);
	usb_fill_bulk_urb(urb, dev->udev,
			usb_rcvbulkpipe(dev->udev, dev->bulk_in_endpointAddr),
			buf, response_length,
			cokey_urb_complete_in_cb, ctx);
	urb->transfer_flags |= URB_FREE_BUFFER;
	usb_anchor_urb(urb, &dev->submitted);
	retval = usb_submit_urb(urb, GFP_KERNEL);
	if (retval) {
		goto error_submit;
	}
#else
	/* single urbs according to current_req_list */
	list_for_each_entry_safe(entry, next, dev->current_req_list, list) {
		buf = kmalloc(entry->response_length, GFP_KERNEL);
		if (!buf) {
			return -ENOMEM;
		}
		ctx = kmalloc(sizeof(struct cokey_in_urb_context), GFP_KERNEL);
		if (!ctx) {
			return -ENOMEM;
		}
		ctx->dev = dev;
		ctx->req = entry->req;
		ctx->req_list = NULL;
		ctx->fast_mode = false;
		urb = usb_alloc_urb(0, GFP_KERNEL);
		usb_fill_bulk_urb(urb, dev->udev,
				usb_rcvbulkpipe(dev->udev, dev->bulk_in_endpointAddr),
				buf, entry->response_length,
				cokey_urb_complete_in_cb, ctx);
		urb->transfer_flags |= URB_FREE_BUFFER;
		usb_anchor_urb(urb, &dev->submitted);
		retval = usb_submit_urb(urb, GFP_KERNEL);
		if (retval) {
			goto error_submit;
		}
		/* remove the entry when submitted */
		list_del(&entry->list);
		kfree(entry);
	}
	kfree(dev->current_req_list);
#endif

	dev->current_req_list = NULL;
	return 0;

error_submit:
	dev_err(&dev->interface->dev,
			"%s - failed submitting urb, error %d\n",
			__func__, retval);

	if (urb) {
		usb_unanchor_urb(urb);
		usb_free_urb(urb);
	}
	if (ctx) {
		kfree(ctx);
	}
	return retval;
}


static int cokey_cmd_try_finish(struct cokey_dev *dev, int
		additional_length)
{
	int urb_max_length, next_required;

	pr_debug("%s enter\n", __func__);

	/* Finish up last command if there is one and it has not enough space to
	 * take the new command or is not a container command */
	if (dev->current_out_urb) {
		if (dev->urb_is_cmd_container) {
			urb_max_length = cokey_usb_packet_length;
			next_required = COKEY_COMMAND_LENGTH;
		} else if (dev->urb_is_fast_mode) {
			urb_max_length = cokey_usb_packet_length_fast;
			next_required = AES_BLOCK_SIZE;
		}

		if ((!dev->urb_is_cmd_container && !dev->urb_is_fast_mode)
		    || (dev->current_out_urb->transfer_buffer_length + next_required + additional_length > urb_max_length))
			return cokey_cmd_finish(dev);
	}
	return 0;
}

static void *cokey_cmd_get_urb_buf(struct cokey_dev *dev, struct cokey_command *cmd, bool fast_mode)
{
	void *ret_buf = NULL;
	void *buf = NULL;
	struct urb *urb = NULL;
	int urb_length;

	if (fast_mode) {
		if (cokey_cmd_try_finish(dev, 0) < 0)
			goto error;
	} else {
		if (cokey_cmd_try_finish(dev, cmd->length) < 0)
			goto error;
	}

	// if switch between fast_mode and non-fast-mode => send
	if (dev->current_out_urb)
		if (dev->urb_is_fast_mode != fast_mode)
			if (cokey_cmd_finish(dev) < 0)
				goto error;


	/* If the last command was finished, current_out_urb should be NULL and
	 * we have to allocate a new URB */
	if (!dev->current_out_urb) {
		if (fast_mode) {
			buf = kmalloc(cokey_usb_packet_length_fast,
					GFP_KERNEL);
			ret_buf = buf;
			urb_length = cmd->length;
			dev->urb_is_fast_mode = true;
			dev->urb_is_cmd_container = false;
		} else if (cmd->length + COKEY_COMMAND_LENGTH >=
				cokey_usb_packet_length) {
			/* send command urb */
			if (cokey_send_command_urb(dev, cmd)) {
				goto error;
			}
			/* allocate a single command data urb */
			buf = kmalloc(cmd->length, GFP_KERNEL);
			ret_buf = buf;
			urb_length = cmd->length;
			dev->urb_is_cmd_container = false;
			dev->urb_is_fast_mode = false;
		} else {
			/* allocate a MIN_USB_PACKET_LENGTH urb */
			buf = kmalloc(cokey_usb_packet_length, GFP_KERNEL);
			/* write command into buffer */
			cokey_fill_buf_from_cmd(buf, cmd);
			ret_buf = buf + COKEY_COMMAND_LENGTH;
			urb_length = COKEY_COMMAND_LENGTH + cmd->length;
			dev->urb_is_cmd_container = true;
			dev->urb_is_fast_mode = false;
		}
		if (!buf) {
			goto error;
		}

		urb = usb_alloc_urb(0, GFP_KERNEL);
		if (!urb) {
			goto error;
		}
		usb_fill_bulk_urb(urb, dev->udev,
				usb_sndbulkpipe(dev->udev, dev->bulk_out_endpointAddr),
				buf, urb_length,
				cokey_urb_complete_out_cb, dev);
		urb->transfer_flags |= URB_FREE_BUFFER;
		dev->current_out_urb = urb;
	} else {
		// Append to current command
		buf = ret_buf = dev->current_out_urb->transfer_buffer +
			dev->current_out_urb->transfer_buffer_length;
		dev->current_out_urb->transfer_buffer_length += cmd->length;
		if (!fast_mode) {
			cokey_fill_buf_from_cmd(buf, cmd);
			ret_buf = buf + COKEY_COMMAND_LENGTH;
			dev->current_out_urb->transfer_buffer_length += COKEY_COMMAND_LENGTH;
		}
	}

	return ret_buf;
error:
	if (buf)
		kfree(buf);
	if (urb)
		usb_free_urb(urb);
	return NULL;
}

static int cokey_cmd_add_request(struct cokey_dev *dev, struct ablkcipher_request *req,
		unsigned int response_length, int cmd_code)
{
	struct req_list_entry *new_entry;

	pr_debug("%s entered\n", __func__);

	/* check if there are any responses already requested, and if not start a new list */
	if (!dev->current_req_list) {
		dev->current_req_list = kmalloc(sizeof(struct list_head),
				GFP_KERNEL);
		if (!dev->current_req_list) {
			pr_err("Could not allocate request list head\n");
			return -ENOMEM;
		}
		INIT_LIST_HEAD(dev->current_req_list);
	}

	new_entry = kmalloc(sizeof(struct req_list_entry), GFP_KERNEL);
	if (!new_entry) {
		pr_err("Could not allocate request list entry\n");
		return -ENOMEM;
	}
	new_entry->req = req;
	new_entry->response_length = response_length;
	new_entry->cmd_code = cmd_code;

	/* insert the req into the current list of reqs to be sent */
	list_add_tail(&new_entry->list, dev->current_req_list);

	return 0;
}

static int cokey_crypt(struct ablkcipher_request *req)
{
	struct crypto_ablkcipher   *tfm    = crypto_ablkcipher_reqtfm(req);
	struct cokey_tfm_ctx         *ctx    = crypto_ablkcipher_ctx(tfm);
	struct cokey_dev *dev = cokey_get_dev_from_tfm(tfm);
	struct cokey_reqctx      *reqctx = ablkcipher_request_ctx(req);

	struct cokey_command cmd;
	int retval;
	void *buf;
	struct list_head *req_list;

	pr_debug("%s enter\n", __func__);

	/* find out if tfm of req is currently active */
	if (!dev->active_tfm_ctx || dev->active_tfm_ctx != ctx) {
	/* req tfm is not active => activate it by sending an setkey URB
	 * if not, activate it by sending a setkey URB before the data and
	 * set it active in cokey_device */
		cmd.code = COKEY_CMD_SETKEY;
		cmd.length = ctx->keylen;
		cmd.tag = 0; //get_random_int(); // TODO USB Protocol Extension

		buf = cokey_cmd_get_urb_buf(dev, &cmd, false);
		if (!buf) {
			retval = -1;
			goto error_cleanup_req;
		}

		memcpy(buf, ctx->aes_key, ctx->keylen);

		if (ctx->fast_mode) {
			retval = cokey_cmd_finish(dev);
			if (retval < 0) {
				goto error_cleanup_req;
			}
		}

		dev->active_tfm_ctx = ctx;

		// TODO USB Protocol Extension: add IN-URB for status response
	}

	if (ctx->fast_mode) {
		/* in fast_mode only the length of cmd has to be set to the
		 * length of the IV */
		cmd.length = AES_BLOCK_SIZE;
	} else {
		/* send the actual crypto command + data */
		cmd.code = reqctx->cmd_code;
		/* length is IV size + actual data */
		cmd.length = AES_BLOCK_SIZE + req->nbytes;
		cmd.tag = 0; //get_random_int(); // TODO USB Protocol Extension
		pr_debug("%s preparing to send %d bytes\n", __func__, req->nbytes);
	}

	buf = cokey_cmd_get_urb_buf(dev, &cmd, ctx->fast_mode);
	if (!buf) {
		retval = -1;
		goto error_cleanup_req;
	}

	/* add request to list with expected response length */
	retval = cokey_cmd_add_request(dev, req, cmd.length, reqctx->cmd_code);
	if (retval < 0) {
		goto error_cleanup_req;
	}

	/* copy the IV to the beginning of the buffer */
	memcpy(buf, req->info, AES_BLOCK_SIZE);

	if (!ctx->fast_mode) {
		/* copy actual data to the urb buffer */
		retval = sg_copy_to_buffer(req->src, sg_nents(req->src), buf+AES_BLOCK_SIZE, req->nbytes);
		if (retval != req->nbytes) {
			pr_err("Could only copy %d/%d bytes from source scatterlist\n", retval, req->nbytes);
			retval = -1;
			goto error;
		}
	}

	return 0;

error_cleanup_req:
	req->base.complete(&req->base, retval);
error:
	/* try to cleanup all the commands/requests that are already in the current out urb */
	if (dev->current_out_urb) {
		usb_unanchor_urb(dev->current_out_urb);
		usb_free_urb(dev->current_out_urb);
		dev->current_out_urb = NULL;
	}

	req_list = dev->current_req_list;
	dev->current_req_list = NULL;

	cokey_cleanup_req_list(req_list, retval);
	return retval;
}

static enum hrtimer_restart cokey_timer_cb(struct hrtimer *t)
{
	struct cokey_dev *dev = container_of(t, struct cokey_dev, timer);
	pr_debug("%s enter\n", __func__);
	tasklet_schedule(&dev->tasklet);
	return HRTIMER_NORESTART;
}

#define COKEY_USB_PACKET_TIMEOUT_MS 1
#define COKEY_USB_PACKET_TIMEOUT_NS 1E4L

static void cokey_tasklet_cb(unsigned long data)
{
        struct cokey_dev *dev = (struct cokey_dev *)data;
        struct crypto_async_request *async_req, *backlog;
        unsigned long flags;

	//hrtimer_try_to_cancel(&dev->timer);

	/* drain the queue */
	while (1) {
		spin_lock_irqsave(&dev->lock, flags);
		backlog   = crypto_get_backlog(&dev->queue);
		async_req = crypto_dequeue_request(&dev->queue);
		spin_unlock_irqrestore(&dev->lock, flags);
		if (backlog) {
			pr_err("backlog\n");
			//cokey_crypt(ablkcipher_request_cast(backlog));
			backlog->complete(backlog, -EINPROGRESS);
			// this should trigger the caller to resubmit the backlogged request
		}
		if (!async_req) {
			/* queue is drained */
			if (!dev->current_out_urb) {
				return;
			}
			/* there is still an out urb to send */
			if ((dev->urb_is_fast_mode && dev->current_out_urb->transfer_buffer_length <= cokey_usb_packet_length_fast/2)
					|| (dev->urb_is_cmd_container && dev->current_out_urb->transfer_buffer_length <= cokey_usb_packet_length/2)) {
				//if (dev->already_tried < 2048) {
				if (dev->already_tried < cokey_usb_packet_short_retries) {
					dev->already_tried++;
					//hrtimer_start(&dev->timer, ms_to_ktime(COKEY_USB_PACKET_TIMEOUT_MS), HRTIMER_MODE_REL);
					//hrtimer_start(&dev->timer, ns_to_ktime(COKEY_USB_PACKET_TIMEOUT_NS), HRTIMER_MODE_REL);
					tasklet_schedule(&dev->tasklet);
					return;
				}
			}
			//dev->already_tried = 0;
			cokey_cmd_finish(dev);
			return;
		}
		dev->already_tried = 0;
		cokey_crypt(ablkcipher_request_cast(async_req));
	}

}

static int cokey_handle_incoming_request(struct ablkcipher_request *req)
{
	struct crypto_ablkcipher   *tfm    = crypto_ablkcipher_reqtfm(req);
	struct cokey_dev *dev = cokey_get_dev_from_tfm(tfm);
        unsigned long flags;
        int err;

	pr_debug("%s enter\n", __func__);

        spin_lock_irqsave(&dev->lock, flags);
        err = ablkcipher_enqueue_request(&dev->queue, req);
        spin_unlock_irqrestore(&dev->lock, flags);

        tasklet_schedule(&dev->tasklet);
        //tasklet_hi_schedule(&dev->tasklet);

        return err;
}

static int cokey_ctr_encrypt(struct ablkcipher_request *req)
{
	struct cokey_reqctx      *reqctx = ablkcipher_request_ctx(req);
	pr_debug("%s enter\n", __func__);

	reqctx->cmd_code = COKEY_CMD_CTR_ENCRYPT;
	return cokey_handle_incoming_request(req);
}

static int cokey_ctr_decrypt(struct ablkcipher_request *req)
{
	struct cokey_reqctx      *reqctx = ablkcipher_request_ctx(req);
	pr_debug("%s enter\n", __func__);

	reqctx->cmd_code = COKEY_CMD_CTR_DECRYPT;
	return cokey_handle_incoming_request(req);
}

#define COKEY_CRA_FLAGS (CRYPTO_ALG_TYPE_ABLKCIPHER | CRYPTO_ALG_ASYNC | CRYPTO_ALG_KERN_DRIVER_ONLY)

static struct crypto_alg cokey_algs[] = {
	{
		.cra_name		= "ctr(aesusbproxy)",
		.cra_driver_name	= "ctr-aesusbproxy",
		.cra_priority		= 100,
		.cra_flags		= COKEY_CRA_FLAGS,
		.cra_blocksize		= AES_BLOCK_SIZE,
		.cra_ctxsize		= sizeof(struct cokey_tfm_ctx),
		.cra_alignmask		= 0x0f,
		.cra_type		= &crypto_ablkcipher_type,
		.cra_module		= THIS_MODULE,
		.cra_init		= cokey_cra_init,
		.cra_exit		= cokey_cra_exit,
		.cra_u.ablkcipher = {
			.min_keysize	= AES_MIN_KEY_SIZE,
			.max_keysize	= AES_MAX_KEY_SIZE,
			.ivsize		= AES_BLOCK_SIZE,
			.setkey		= cokey_setkey,
			.encrypt	= cokey_ctr_encrypt,
			.decrypt	= cokey_ctr_decrypt,
		}
	},
	{
		.cra_name		= "ctr(aesusb)",
		.cra_driver_name	= "ctr-aesusb",
		.cra_priority		= 100,
		.cra_flags		= COKEY_CRA_FLAGS,
		.cra_blocksize		= AES_BLOCK_SIZE,
		.cra_ctxsize		= sizeof(struct cokey_tfm_ctx),
		.cra_alignmask		= 0x0f,
		.cra_type		= &crypto_ablkcipher_type,
		.cra_module		= THIS_MODULE,
		.cra_init		= cokey_cra_fast_init,
		.cra_exit		= cokey_cra_exit,
		.cra_u.ablkcipher = {
			.min_keysize	= AES_MIN_KEY_SIZE,
			.max_keysize	= AES_MAX_KEY_SIZE,
			.ivsize		= AES_BLOCK_SIZE,
			.setkey		= cokey_setkey,
			.encrypt	= cokey_ctr_encrypt,
			.decrypt	= cokey_ctr_decrypt,
		}
	},
};

static int cokey_probe(struct usb_interface *interface,
		      const struct usb_device_id *id)
{
	struct cokey_dev *dev;
	struct usb_host_interface *iface_desc;
	struct usb_endpoint_descriptor *endpoint;
	size_t buffer_size;
	int i, j;
	int retval = -ENOMEM;

	if (cokey_device) {
		dev_err(&interface->dev, "Driver can only handle one device...");
		return -1;
	}

	/* allocate memory for our device state and initialize it */
	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev) {
		dev_err(&interface->dev, "Out of memory\n");
		goto error;
	}
	kref_init(&dev->kref);
	init_usb_anchor(&dev->submitted);

	spin_lock_init(&dev->lock);

	tasklet_init(&dev->tasklet, cokey_tasklet_cb, (unsigned long)dev);

	hrtimer_init(&dev->timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
	dev->timer.function = &cokey_timer_cb;

	// TODO use normal or high priority workqueue?
	dev->wq_urb = alloc_workqueue("%s", 0, 0, "cokey");
	//dev->wq_urb = alloc_workqueue("%s", WQ_HIGHPRI, 0, "cokey");

	dev->udev = usb_get_dev(interface_to_usbdev(interface));
	dev->interface = interface;

	/* set up the endpoint information */
	/* use only the first bulk-in and bulk-out endpoints */
	iface_desc = interface->cur_altsetting;
	for (i = 0; i < iface_desc->desc.bNumEndpoints; ++i) {
		endpoint = &iface_desc->endpoint[i].desc;

		if (!dev->bulk_in_endpointAddr &&
		    usb_endpoint_is_bulk_in(endpoint)) {
			/* we found a bulk in endpoint */
			buffer_size = usb_endpoint_maxp(endpoint);
			dev->bulk_in_endpointAddr = endpoint->bEndpointAddress;
		}

		if (!dev->bulk_out_endpointAddr &&
		    usb_endpoint_is_bulk_out(endpoint)) {
			/* we found a bulk out endpoint */
			dev->bulk_out_endpointAddr = endpoint->bEndpointAddress;
		}
	}
	if (!(dev->bulk_in_endpointAddr && dev->bulk_out_endpointAddr)) {
		dev_err(&interface->dev,
			"Could not find both bulk-in and bulk-out endpoints\n");
		goto error;
	}

	/* save our data pointer in this interface device */
	usb_set_intfdata(interface, dev);

	/* let the user know what node this device is now attached to */
	dev_info(&interface->dev,
		 "cokey device now attached");

	cokey_device = dev;

	/********************/
	/* Crypto API stuff */
	crypto_init_queue(&dev->queue, CRYPTO_QUEUE_LEN);

	/* register algs */
	for (i = 0; i < ARRAY_SIZE(cokey_algs); i++) {
		/* reset alg flags which seems to be necessary when the device is
		 * re-registered. When unregistering an alg, the crypto API sets the
		 * CRYPTO_ALG_DEAD flag in cra_flags which prevents another registering
		 * if the module is not unloaded... */
		cokey_algs[i].cra_flags = COKEY_CRA_FLAGS;
		retval = crypto_register_alg(&cokey_algs[i]);
		if (retval)
			goto err_algs;
	}

	return 0;

err_algs:
	dev_err(&interface->dev, "can't register '%s': %d\n", cokey_algs[i].cra_name, retval);

	for (j = 0; j < i; j++)
		crypto_unregister_alg(&cokey_algs[j]);

error:
	cokey_device = NULL;

	if (dev)
		/* this frees allocated memory */
		kref_put(&dev->kref, cokey_delete);
	return retval;
}

/* TODO handle disconnects when CoKey is in use gracefully */
static void cokey_disconnect(struct usb_interface *interface)
{
	struct cokey_dev *dev;
	int i;

	dev = usb_get_intfdata(interface);
	usb_set_intfdata(interface, NULL);

	/* prevent more I/O from starting */
	//mutex_lock(&dev->io_mutex);
	dev->interface = NULL;
	//mutex_unlock(&dev->io_mutex);

	usb_kill_anchored_urbs(&dev->submitted);

	/* decrement our usage count */
	kref_put(&dev->kref, cokey_delete);

	/********************/
	/* crypto API stuff */
	for (i = 0; i < ARRAY_SIZE(cokey_algs); i++)
		crypto_unregister_alg(&cokey_algs[i]);
	cokey_device = NULL;

	dev_info(&interface->dev, "cokey now disconnected");
}


static struct usb_driver cokey_driver = {
	.name =		"cokey",
	.probe =	cokey_probe,
	.disconnect =	cokey_disconnect,
	.id_table =	cokey_table,
};

module_usb_driver(cokey_driver);

MODULE_LICENSE("GPL");
