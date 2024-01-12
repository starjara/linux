#include <linux/mini_host.h>
#include <linux/kvm_host.h>
#include <linux/mini.h>
#include <linux/errno.h>
#include <linux/uaccess.h>

ssize_t mini_stats_read(char *id, const struct kvm_stats_header *header,
		       const struct _kvm_stats_desc *desc,
		       void *stats, size_t size_stats,
		       char __user *user_buffer, size_t size, loff_t *offset)
{
	ssize_t len;
	ssize_t copylen;
	ssize_t remain = size;
	size_t size_desc;
	size_t size_header;
	void *src;
	loff_t pos = *offset;
	char __user *dest = user_buffer;

	size_header = sizeof(*header);
	size_desc = header->num_desc * sizeof(*desc);

	len = MINI_STATS_NAME_SIZE + size_header + size_desc + size_stats - pos;
	len = min(len, remain);
	if (len <= 0)
		return 0;
	remain = len;

	/*
	 * Copy mini stats header.
	 * The header is the first block of content userspace usually read out.
	 * The pos is 0 and the copylen and remain would be the size of header.
	 * The copy of the header would be skipped if offset is larger than the
	 * size of header. That usually happens when userspace reads stats
	 * descriptors and stats data.
	 */
	copylen = size_header - pos;
	copylen = min(copylen, remain);
	if (copylen > 0) {
		src = (void *)header + pos;
		if (copy_to_user(dest, src, copylen))
			return -EFAULT;
		remain -= copylen;
		pos += copylen;
		dest += copylen;
	}

	/*
	 * Copy mini stats header id string.
	 * The id string is unique for every vm/vcpu, which is stored in mini
	 * and mini_vcpu structure.
	 * The id string is part of the stat header from the perspective of
	 * userspace, it is usually read out together with previous constant
	 * header part and could be skipped for later descriptors and stats
	 * data readings.
	 */
	copylen = header->id_offset + MINI_STATS_NAME_SIZE - pos;
	copylen = min(copylen, remain);
	if (copylen > 0) {
		src = id + pos - header->id_offset;
		if (copy_to_user(dest, src, copylen))
			return -EFAULT;
		remain -= copylen;
		pos += copylen;
		dest += copylen;
	}

	/*
	 * Copy mini stats descriptors.
	 * The descriptors copy would be skipped in the typical case that
	 * userspace periodically read stats data, since the pos would be
	 * greater than the end address of descriptors
	 * (header->header.desc_offset + size_desc) causing copylen <= 0.
	 */
	copylen = header->desc_offset + size_desc - pos;
	copylen = min(copylen, remain);
	if (copylen > 0) {
		src = (void *)desc + pos - header->desc_offset;
		if (copy_to_user(dest, src, copylen))
			return -EFAULT;
		remain -= copylen;
		pos += copylen;
		dest += copylen;
	}

	/* Copy mini stats values */
	copylen = header->data_offset + size_stats - pos;
	copylen = min(copylen, remain);
	if (copylen > 0) {
		src = stats + pos - header->data_offset;
		if (copy_to_user(dest, src, copylen))
			return -EFAULT;
		pos += copylen;
    }

	*offset = pos;
    return len;
}

