/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/* THIS FILE IS AUTOGENERATED! */
#ifndef __XDP_REDIRECT_MAP_BPF_SKEL_H__
#define __XDP_REDIRECT_MAP_BPF_SKEL_H__

#include <stdlib.h>
#include <bpf/libbpf.h>

struct xdp_redirect_map_bpf {
	struct bpf_object_skeleton *skeleton;
	struct bpf_object *obj;
	struct {
		struct bpf_map *rxcnt;
		struct bpf_map *tx_port;
	} maps;
	struct {
		struct bpf_program *xdp_redirect_map_prog;
		struct bpf_program *xdp_redirect_dummy_prog;
	} progs;
	struct {
		struct bpf_link *xdp_redirect_map_prog;
		struct bpf_link *xdp_redirect_dummy_prog;
	} links;
};

static void
xdp_redirect_map_bpf__destroy(struct xdp_redirect_map_bpf *obj)
{
	if (!obj)
		return;
	if (obj->skeleton)
		bpf_object__destroy_skeleton(obj->skeleton);
	free(obj);
}

static inline int
xdp_redirect_map_bpf__create_skeleton(struct xdp_redirect_map_bpf *obj);

static inline struct xdp_redirect_map_bpf *
xdp_redirect_map_bpf__open_opts(const struct bpf_object_open_opts *opts)
{
	struct xdp_redirect_map_bpf *obj;

	obj = (struct xdp_redirect_map_bpf *)calloc(1, sizeof(*obj));
	if (!obj)
		return NULL;
	if (xdp_redirect_map_bpf__create_skeleton(obj))
		goto err;
	if (bpf_object__open_skeleton(obj->skeleton, opts))
		goto err;

	return obj;
err:
	xdp_redirect_map_bpf__destroy(obj);
	return NULL;
}

static inline struct xdp_redirect_map_bpf *
xdp_redirect_map_bpf__open(void)
{
	return xdp_redirect_map_bpf__open_opts(NULL);
}

static inline int
xdp_redirect_map_bpf__load(struct xdp_redirect_map_bpf *obj)
{
	return bpf_object__load_skeleton(obj->skeleton);
}

static inline struct xdp_redirect_map_bpf *
xdp_redirect_map_bpf__open_and_load(void)
{
	struct xdp_redirect_map_bpf *obj;

	obj = xdp_redirect_map_bpf__open();
	if (!obj)
		return NULL;
	if (xdp_redirect_map_bpf__load(obj)) {
		xdp_redirect_map_bpf__destroy(obj);
		return NULL;
	}
	return obj;
}

static inline int
xdp_redirect_map_bpf__attach(struct xdp_redirect_map_bpf *obj)
{
	return bpf_object__attach_skeleton(obj->skeleton);
}

static inline void
xdp_redirect_map_bpf__detach(struct xdp_redirect_map_bpf *obj)
{
	return bpf_object__detach_skeleton(obj->skeleton);
}

static inline int
xdp_redirect_map_bpf__create_skeleton(struct xdp_redirect_map_bpf *obj)
{
	struct bpf_object_skeleton *s;

	s = (struct bpf_object_skeleton *)calloc(1, sizeof(*s));
	if (!s)
		return -1;
	obj->skeleton = s;

	s->sz = sizeof(*s);
	s->name = "xdp_redirect_map_bpf";
	s->obj = &obj->obj;

	/* maps */
	s->map_cnt = 2;
	s->map_skel_sz = sizeof(*s->maps);
	s->maps = (struct bpf_map_skeleton *)calloc(s->map_cnt, s->map_skel_sz);
	if (!s->maps)
		goto err;

	s->maps[0].name = "rxcnt";
	s->maps[0].map = &obj->maps.rxcnt;

	s->maps[1].name = "tx_port";
	s->maps[1].map = &obj->maps.tx_port;

	/* programs */
	s->prog_cnt = 2;
	s->prog_skel_sz = sizeof(*s->progs);
	s->progs = (struct bpf_prog_skeleton *)calloc(s->prog_cnt, s->prog_skel_sz);
	if (!s->progs)
		goto err;

	s->progs[0].name = "xdp_redirect_map_prog";
	s->progs[0].prog = &obj->progs.xdp_redirect_map_prog;
	s->progs[0].link = &obj->links.xdp_redirect_map_prog;

	s->progs[1].name = "xdp_redirect_dummy_prog";
	s->progs[1].prog = &obj->progs.xdp_redirect_dummy_prog;
	s->progs[1].link = &obj->links.xdp_redirect_dummy_prog;

	s->data_sz = 4368;
	s->data = (void *)"\
\x7f\x45\x4c\x46\x02\x01\x01\0\0\0\0\0\0\0\0\0\x01\0\xf7\0\x01\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x90\x0d\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\x40\0\x0e\0\
\x0d\0\x61\x12\x04\0\0\0\0\0\x61\x16\0\0\0\0\0\0\xb7\x01\0\0\0\0\0\0\x63\x1a\
\xfc\xff\0\0\0\0\xb7\0\0\0\x01\0\0\0\xbf\x61\0\0\0\0\0\0\x07\x01\0\0\x0e\0\0\0\
\x2d\x21\x1a\0\0\0\0\0\xbf\xa2\0\0\0\0\0\0\x07\x02\0\0\xfc\xff\xff\xff\x18\x01\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x85\0\0\0\x01\0\0\0\x15\0\x03\0\0\0\0\0\x79\x01\0\
\0\0\0\0\0\x07\x01\0\0\x01\0\0\0\x7b\x10\0\0\0\0\0\0\x69\x61\0\0\0\0\0\0\x69\
\x62\x06\0\0\0\0\0\x6b\x26\0\0\0\0\0\0\x69\x62\x08\0\0\0\0\0\x69\x63\x02\0\0\0\
\0\0\x6b\x36\x08\0\0\0\0\0\x6b\x26\x02\0\0\0\0\0\x69\x62\x0a\0\0\0\0\0\x69\x63\
\x04\0\0\0\0\0\x6b\x36\x0a\0\0\0\0\0\x6b\x16\x06\0\0\0\0\0\x6b\x26\x04\0\0\0\0\
\0\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb7\x02\0\0\0\0\0\0\xb7\x03\0\0\0\0\0\0\
\x85\0\0\0\x33\0\0\0\x95\0\0\0\0\0\0\0\xb7\0\0\0\x02\0\0\0\x95\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x47\x50\x4c\0\x9f\xeb\x01\0\
\x18\0\0\0\0\0\0\0\xd0\x02\0\0\xd0\x02\0\0\x1c\x03\0\0\0\0\0\0\0\0\0\x02\x03\0\
\0\0\x01\0\0\0\0\0\0\x01\x04\0\0\0\x20\0\0\x01\0\0\0\0\0\0\0\x03\0\0\0\0\x02\0\
\0\0\x04\0\0\0\x06\0\0\0\x05\0\0\0\0\0\0\x01\x04\0\0\0\x20\0\0\0\0\0\0\0\0\0\0\
\x02\x06\0\0\0\x19\0\0\0\0\0\0\x08\x07\0\0\0\x1d\0\0\0\0\0\0\x08\x08\0\0\0\x23\
\0\0\0\0\0\0\x01\x04\0\0\0\x20\0\0\0\0\0\0\0\0\0\0\x02\x0a\0\0\0\x30\0\0\0\0\0\
\0\x01\x08\0\0\0\x40\0\0\x01\0\0\0\0\0\0\0\x02\x0c\0\0\0\0\0\0\0\0\0\0\x03\0\0\
\0\0\x02\0\0\0\x04\0\0\0\x01\0\0\0\0\0\0\0\x04\0\0\x04\x20\0\0\0\x39\0\0\0\x01\
\0\0\0\0\0\0\0\x3e\0\0\0\x05\0\0\0\x40\0\0\0\x42\0\0\0\x09\0\0\0\x80\0\0\0\x48\
\0\0\0\x0b\0\0\0\xc0\0\0\0\x54\0\0\0\0\0\0\x0e\x0d\0\0\0\x01\0\0\0\0\0\0\0\0\0\
\0\x02\x10\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\x02\0\0\0\x04\0\0\0\x0e\0\0\0\0\0\0\
\0\0\0\0\x02\x12\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\x02\0\0\0\x04\0\0\0\x04\0\0\0\
\0\0\0\0\0\0\0\x02\x14\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\0\x02\0\0\0\x04\0\0\0\x64\
\0\0\0\0\0\0\0\x04\0\0\x04\x20\0\0\0\x39\0\0\0\x0f\0\0\0\0\0\0\0\x5a\0\0\0\x11\
\0\0\0\x40\0\0\0\x63\0\0\0\x11\0\0\0\x80\0\0\0\x48\0\0\0\x13\0\0\0\xc0\0\0\0\
\x6e\0\0\0\0\0\0\x0e\x15\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\x02\x18\0\0\0\x76\0\0\0\
\x06\0\0\x04\x18\0\0\0\x7d\0\0\0\x07\0\0\0\0\0\0\0\x82\0\0\0\x07\0\0\0\x20\0\0\
\0\x8b\0\0\0\x07\0\0\0\x40\0\0\0\x95\0\0\0\x07\0\0\0\x60\0\0\0\xa5\0\0\0\x07\0\
\0\0\x80\0\0\0\xb4\0\0\0\x07\0\0\0\xa0\0\0\0\0\0\0\0\x01\0\0\x0d\x02\0\0\0\xc3\
\0\0\0\x17\0\0\0\xc7\0\0\0\x01\0\0\x0c\x19\0\0\0\0\0\0\0\x01\0\0\x0d\x02\0\0\0\
\xc3\0\0\0\x17\0\0\0\xb8\x02\0\0\x01\0\0\x0c\x1b\0\0\0\0\x03\0\0\0\0\0\x01\x01\
\0\0\0\x08\0\0\x01\0\0\0\0\0\0\0\x03\0\0\0\0\x1d\0\0\0\x04\0\0\0\x04\0\0\0\x05\
\x03\0\0\0\0\0\x0e\x1e\0\0\0\x01\0\0\0\x0e\x03\0\0\x02\0\0\x0f\0\0\0\0\x0e\0\0\
\0\0\0\0\0\x20\0\0\0\x16\0\0\0\0\0\0\0\x20\0\0\0\x14\x03\0\0\x01\0\0\x0f\0\0\0\
\0\x1f\0\0\0\0\0\0\0\x04\0\0\0\0\x69\x6e\x74\0\x5f\x5f\x41\x52\x52\x41\x59\x5f\
\x53\x49\x5a\x45\x5f\x54\x59\x50\x45\x5f\x5f\0\x75\x33\x32\0\x5f\x5f\x75\x33\
\x32\0\x75\x6e\x73\x69\x67\x6e\x65\x64\x20\x69\x6e\x74\0\x6c\x6f\x6e\x67\x20\
\x69\x6e\x74\0\x74\x79\x70\x65\0\x6b\x65\x79\0\x76\x61\x6c\x75\x65\0\x6d\x61\
\x78\x5f\x65\x6e\x74\x72\x69\x65\x73\0\x72\x78\x63\x6e\x74\0\x6b\x65\x79\x5f\
\x73\x69\x7a\x65\0\x76\x61\x6c\x75\x65\x5f\x73\x69\x7a\x65\0\x74\x78\x5f\x70\
\x6f\x72\x74\0\x78\x64\x70\x5f\x6d\x64\0\x64\x61\x74\x61\0\x64\x61\x74\x61\x5f\
\x65\x6e\x64\0\x64\x61\x74\x61\x5f\x6d\x65\x74\x61\0\x69\x6e\x67\x72\x65\x73\
\x73\x5f\x69\x66\x69\x6e\x64\x65\x78\0\x72\x78\x5f\x71\x75\x65\x75\x65\x5f\x69\
\x6e\x64\x65\x78\0\x65\x67\x72\x65\x73\x73\x5f\x69\x66\x69\x6e\x64\x65\x78\0\
\x63\x74\x78\0\x78\x64\x70\x5f\x72\x65\x64\x69\x72\x65\x63\x74\x5f\x6d\x61\x70\
\x5f\x70\x72\x6f\x67\0\x78\x64\x70\x5f\x64\x65\x76\x6d\x61\x70\x2f\x78\x64\x70\
\x5f\x72\x65\x64\x69\x72\x65\x63\x74\x5f\x6d\x61\x70\0\x30\x3a\x31\0\x2f\x68\
\x6f\x6d\x65\x2f\x78\x64\x70\x2d\x74\x65\x73\x74\x2f\x78\x64\x70\x5f\x72\x65\
\x64\x69\x72\x65\x63\x74\x2f\x78\x64\x70\x5f\x72\x65\x64\x69\x72\x65\x63\x74\
\x5f\x6d\x61\x70\x2e\x62\x70\x66\x2e\x63\0\x09\x76\x6f\x69\x64\x20\x2a\x64\x61\
\x74\x61\x5f\x65\x6e\x64\x20\x3d\x20\x28\x76\x6f\x69\x64\x20\x2a\x29\x28\x6c\
\x6f\x6e\x67\x29\x63\x74\x78\x2d\x3e\x64\x61\x74\x61\x5f\x65\x6e\x64\x3b\0\x30\
\x3a\x30\0\x09\x76\x6f\x69\x64\x20\x2a\x64\x61\x74\x61\x20\x3d\x20\x28\x76\x6f\
\x69\x64\x20\x2a\x29\x28\x6c\x6f\x6e\x67\x29\x63\x74\x78\x2d\x3e\x64\x61\x74\
\x61\x3b\0\x09\x75\x33\x32\x20\x6b\x65\x79\x20\x3d\x20\x30\x3b\0\x09\x69\x66\
\x20\x28\x64\x61\x74\x61\x20\x2b\x20\x6e\x68\x5f\x6f\x66\x66\x20\x3e\x20\x64\
\x61\x74\x61\x5f\x65\x6e\x64\x29\0\x09\x76\x61\x6c\x75\x65\x20\x3d\x20\x62\x70\
\x66\x5f\x6d\x61\x70\x5f\x6c\x6f\x6f\x6b\x75\x70\x5f\x65\x6c\x65\x6d\x28\x26\
\x72\x78\x63\x6e\x74\x2c\x20\x26\x6b\x65\x79\x29\x3b\0\x09\x69\x66\x20\x28\x76\
\x61\x6c\x75\x65\x29\0\x09\x09\x2a\x76\x61\x6c\x75\x65\x20\x2b\x3d\x20\x31\x3b\
\0\x09\x64\x73\x74\x5b\x30\x5d\x20\x3d\x20\x70\x5b\x30\x5d\x3b\0\x09\x70\x5b\
\x30\x5d\x20\x3d\x20\x70\x5b\x33\x5d\x3b\0\x09\x70\x5b\x31\x5d\x20\x3d\x20\x70\
\x5b\x34\x5d\x3b\0\x09\x64\x73\x74\x5b\x31\x5d\x20\x3d\x20\x70\x5b\x31\x5d\x3b\
\0\x09\x70\x5b\x34\x5d\x20\x3d\x20\x64\x73\x74\x5b\x31\x5d\x3b\0\x09\x70\x5b\
\x32\x5d\x20\x3d\x20\x70\x5b\x35\x5d\x3b\0\x09\x64\x73\x74\x5b\x32\x5d\x20\x3d\
\x20\x70\x5b\x32\x5d\x3b\0\x09\x70\x5b\x35\x5d\x20\x3d\x20\x64\x73\x74\x5b\x32\
\x5d\x3b\0\x09\x70\x5b\x33\x5d\x20\x3d\x20\x64\x73\x74\x5b\x30\x5d\x3b\0\x09\
\x72\x65\x74\x75\x72\x6e\x20\x62\x70\x66\x5f\x72\x65\x64\x69\x72\x65\x63\x74\
\x5f\x6d\x61\x70\x28\x26\x74\x78\x5f\x70\x6f\x72\x74\x2c\x20\x76\x70\x6f\x72\
\x74\x2c\x20\x30\x29\x3b\0\x7d\0\x78\x64\x70\x5f\x72\x65\x64\x69\x72\x65\x63\
\x74\x5f\x64\x75\x6d\x6d\x79\x5f\x70\x72\x6f\x67\0\x78\x64\x70\x5f\x64\x65\x76\
\x6d\x61\x70\x2f\x78\x64\x70\x5f\x72\x65\x64\x69\x72\x65\x63\x74\x5f\x64\x75\
\x6d\x6d\x79\0\x09\x72\x65\x74\x75\x72\x6e\x20\x58\x44\x50\x5f\x50\x41\x53\x53\
\x3b\0\x63\x68\x61\x72\0\x5f\x6c\x69\x63\x65\x6e\x73\x65\0\x2e\x6d\x61\x70\x73\
\0\x6c\x69\x63\x65\x6e\x73\x65\0\x9f\xeb\x01\0\x20\0\0\0\0\0\0\0\x24\0\0\0\x24\
\0\0\0\x94\x01\0\0\xb8\x01\0\0\x2c\0\0\0\x08\0\0\0\xdd\0\0\0\x01\0\0\0\0\0\0\0\
\x1a\0\0\0\xd0\x02\0\0\x01\0\0\0\0\0\0\0\x1c\0\0\0\x10\0\0\0\xdd\0\0\0\x17\0\0\
\0\0\0\0\0\xfd\0\0\0\x30\x01\0\0\x26\xd0\0\0\x08\0\0\0\xfd\0\0\0\x63\x01\0\0\
\x22\xd4\0\0\x18\0\0\0\xfd\0\0\0\x8a\x01\0\0\x06\xe8\0\0\x28\0\0\0\xfd\0\0\0\
\x98\x01\0\0\x0b\xf8\0\0\x38\0\0\0\xfd\0\0\0\x98\x01\0\0\x06\xf8\0\0\x48\0\0\0\
\xfd\0\0\0\0\0\0\0\0\0\0\0\x50\0\0\0\xfd\0\0\0\xb7\x01\0\0\x0a\x14\x01\0\x68\0\
\0\0\xfd\0\0\0\xe3\x01\0\0\x06\x18\x01\0\x70\0\0\0\xfd\0\0\0\xef\x01\0\0\x0a\
\x1c\x01\0\x88\0\0\0\xfd\0\0\0\xfe\x01\0\0\x0b\x98\0\0\x90\0\0\0\xfd\0\0\0\x0e\
\x02\0\0\x09\xa4\0\0\x98\0\0\0\xfd\0\0\0\x0e\x02\0\0\x07\xa4\0\0\xa0\0\0\0\xfd\
\0\0\0\x1c\x02\0\0\x09\xa8\0\0\xa8\0\0\0\xfd\0\0\0\x2a\x02\0\0\x0b\x9c\0\0\xb0\
\0\0\0\xfd\0\0\0\x3a\x02\0\0\x07\xb4\0\0\xb8\0\0\0\xfd\0\0\0\x1c\x02\0\0\x07\
\xa8\0\0\xc0\0\0\0\xfd\0\0\0\x4a\x02\0\0\x09\xac\0\0\xc8\0\0\0\xfd\0\0\0\x58\
\x02\0\0\x0b\xa0\0\0\xd0\0\0\0\xfd\0\0\0\x68\x02\0\0\x07\xb8\0\0\xd8\0\0\0\xfd\
\0\0\0\x78\x02\0\0\x07\xb0\0\0\xe0\0\0\0\xfd\0\0\0\x4a\x02\0\0\x07\xac\0\0\xe8\
\0\0\0\xfd\0\0\0\x88\x02\0\0\x09\x30\x01\0\x10\x01\0\0\xfd\0\0\0\xb6\x02\0\0\
\x01\x34\x01\0\xd0\x02\0\0\x01\0\0\0\0\0\0\0\xfd\0\0\0\xee\x02\0\0\x02\x4c\x01\
\0\x10\0\0\0\xdd\0\0\0\x02\0\0\0\0\0\0\0\x18\0\0\0\xf9\0\0\0\0\0\0\0\x08\0\0\0\
\x18\0\0\0\x5f\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\xcb\0\0\0\0\0\x02\0\x88\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xc4\0\0\0\0\0\
\x02\0\x10\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x02\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\x03\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xa2\0\0\0\
\x11\0\x05\0\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\x3a\0\0\0\x11\0\x04\0\0\0\0\0\0\
\0\0\0\x20\0\0\0\0\0\0\0\x32\0\0\0\x11\0\x04\0\x20\0\0\0\0\0\0\0\x20\0\0\0\0\0\
\0\0\x66\0\0\0\x12\0\x03\0\0\0\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\x7e\0\0\0\x12\0\
\x02\0\0\0\0\0\0\0\0\0\x18\x01\0\0\0\0\0\0\x50\0\0\0\0\0\0\0\x01\0\0\0\x06\0\0\
\0\xe8\0\0\0\0\0\0\0\x01\0\0\0\x07\0\0\0\xbc\x02\0\0\0\0\0\0\0\0\0\0\x06\0\0\0\
\xc8\x02\0\0\0\0\0\0\0\0\0\0\x07\0\0\0\xe0\x02\0\0\0\0\0\0\0\0\0\0\x05\0\0\0\
\x2c\0\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\x3c\0\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\x50\0\
\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\x60\0\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\x70\0\0\0\0\
\0\0\0\0\0\0\0\x03\0\0\0\x80\0\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\x90\0\0\0\0\0\0\0\
\0\0\0\0\x03\0\0\0\xa0\0\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\xb0\0\0\0\0\0\0\0\0\0\0\
\0\x03\0\0\0\xc0\0\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\xd0\0\0\0\0\0\0\0\0\0\0\0\x03\
\0\0\0\xe0\0\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\xf0\0\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\
\0\x01\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\x10\x01\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\x20\
\x01\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\x30\x01\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\x40\
\x01\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\x50\x01\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\x60\
\x01\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\x70\x01\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\x80\
\x01\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\x90\x01\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\xa0\
\x01\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\xb0\x01\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\xc8\
\x01\0\0\0\0\0\0\0\0\0\0\x04\0\0\0\xe4\x01\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\xf4\
\x01\0\0\0\0\0\0\0\0\0\0\x03\0\0\0\x10\x0f\x0d\x0e\x0c\0\x78\x64\x70\x5f\x64\
\x65\x76\x6d\x61\x70\x2f\x78\x64\x70\x5f\x72\x65\x64\x69\x72\x65\x63\x74\x5f\
\x64\x75\x6d\x6d\x79\0\x2e\x74\x65\x78\x74\0\x2e\x72\x65\x6c\x2e\x42\x54\x46\
\x2e\x65\x78\x74\0\x74\x78\x5f\x70\x6f\x72\x74\0\x72\x78\x63\x6e\x74\0\x2e\x6d\
\x61\x70\x73\0\x2e\x72\x65\x6c\x78\x64\x70\x5f\x64\x65\x76\x6d\x61\x70\x2f\x78\
\x64\x70\x5f\x72\x65\x64\x69\x72\x65\x63\x74\x5f\x6d\x61\x70\0\x78\x64\x70\x5f\
\x72\x65\x64\x69\x72\x65\x63\x74\x5f\x64\x75\x6d\x6d\x79\x5f\x70\x72\x6f\x67\0\
\x78\x64\x70\x5f\x72\x65\x64\x69\x72\x65\x63\x74\x5f\x6d\x61\x70\x5f\x70\x72\
\x6f\x67\0\x2e\x6c\x6c\x76\x6d\x5f\x61\x64\x64\x72\x73\x69\x67\0\x5f\x6c\x69\
\x63\x65\x6e\x73\x65\0\x2e\x73\x74\x72\x74\x61\x62\0\x2e\x73\x79\x6d\x74\x61\
\x62\0\x2e\x72\x65\x6c\x2e\x42\x54\x46\0\x4c\x42\x42\x30\x5f\x34\0\x4c\x42\x42\
\x30\x5f\x33\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x1f\0\0\0\
\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x4a\0\0\0\x01\0\0\0\x06\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\x18\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\x08\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\x01\0\0\0\x06\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\x58\x01\0\0\0\0\0\0\x10\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\0\x40\0\0\0\x01\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\x68\x01\0\0\0\0\0\0\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x08\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\xa3\0\0\0\x01\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xa8\x01\0\0\0\
\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xbf\
\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xac\x01\0\0\0\0\0\0\x04\x06\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x29\0\0\0\x01\0\0\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb0\x07\0\0\0\0\0\0\x04\x02\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xb3\0\0\0\x02\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\0\0\0\0\0\xb8\x09\0\0\0\0\0\0\xf0\0\0\0\0\0\0\0\x0d\0\0\0\x05\0\0\0\
\x08\0\0\0\0\0\0\0\x18\0\0\0\0\0\0\0\x46\0\0\0\x09\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\0\0\0\0\xa8\x0a\0\0\0\0\0\0\x20\0\0\0\0\0\0\0\x08\0\0\0\x02\0\0\0\x08\0\0\0\
\0\0\0\0\x10\0\0\0\0\0\0\0\xbb\0\0\0\x09\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\xc8\x0a\0\0\0\0\0\0\x30\0\0\0\0\0\0\0\x08\0\0\0\x06\0\0\0\x08\0\0\0\0\0\0\0\
\x10\0\0\0\0\0\0\0\x25\0\0\0\x09\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xf8\x0a\
\0\0\0\0\0\0\xc0\x01\0\0\0\0\0\0\x08\0\0\0\x07\0\0\0\x08\0\0\0\0\0\0\0\x10\0\0\
\0\0\0\0\0\x94\0\0\0\x03\x4c\xff\x6f\0\0\0\x80\0\0\0\0\0\0\0\0\0\0\0\0\xb8\x0c\
\0\0\0\0\0\0\x05\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\
\0\xab\0\0\0\x03\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xbd\x0c\0\0\0\0\0\0\xd2\
\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

	return 0;
err:
	bpf_object__destroy_skeleton(s);
	return -1;
}

#endif /* __XDP_REDIRECT_MAP_BPF_SKEL_H__ */
