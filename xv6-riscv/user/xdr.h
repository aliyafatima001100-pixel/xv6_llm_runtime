#ifndef _RPC_XDR_H_
#define _RPC_XDR_H_

#include "../kernel/types.h"

/* XDR operation types */
enum xdr_op {
    XDR_ENCODE = 0,
    XDR_DECODE = 1,
    XDR_FREE = 2
};

/* XDR data types */
typedef int (*xdrproc_t)(void *, void *);
typedef unsigned int u_int;
typedef int bool_t;
typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned long u_long;
typedef long long quad_t;
typedef unsigned long long u_quad_t;
typedef int enum_t;

/* XDR stream structure */
typedef struct {
    enum xdr_op x_op;           /* operation; fast to check */
    struct xdr_ops *x_ops;      /* xdr stream operations */
    char *x_private;            /* private used by the xdr ops */
    char *x_base;               /* private used to align data */
    u_int x_handy;              /* extra private word */
} XDR;

/* XDR stream operations */
struct xdr_ops {
    /* get a long from underlying stream */
    int (*x_getlong)(XDR *, long *);
    /* put a long to underlying stream */
    int (*x_putlong)(XDR *, long *);
    /* get some bytes from underlying stream */
    int (*x_getbytes)(XDR *, char *, u_int);
    /* put some bytes to underlying stream */
    int (*x_putbytes)(XDR *, char *, u_int);
    /* returns bytes unused in underlying stream */
    u_int (*x_getpos)(XDR *);
    /* reposition the stream */
    int (*x_setpos)(XDR *, u_int);
    /* get a contiguous chunk of the stream */
    long * (*x_inline)(XDR *, int);
    /* destroy stream */
    void (*x_destroy)(XDR *);
};

/* Macros */
#define XDR_GETPOS(xdrs)        (*(xdrs)->x_ops->x_getpos)(xdrs)
#define XDR_SETPOS(xdrs, pos)   (*(xdrs)->x_ops->x_setpos)(xdrs, pos)
#define XDR_DESTROY(xdrs)       (*(xdrs)->x_ops->x_destroy)(xdrs)
#define XDR_INLINE(xdrs, len)   (*(xdrs)->x_ops->x_inline)(xdrs, len)

/* Primitive XDR routines */
int xdr_void(void);
int xdr_bool(XDR *, bool_t *);
int xdr_char(XDR *, char *);
int xdr_u_char(XDR *, u_char *);
int xdr_short(XDR *, short *);
int xdr_u_short(XDR *, u_short *);
int xdr_int(XDR *, int *);
int xdr_u_int(XDR *, u_int *);
int xdr_long(XDR *, long *);
int xdr_u_long(XDR *, u_long *);
int xdr_hyper(XDR *, quad_t *);
int xdr_u_hyper(XDR *, u_quad_t *);
int xdr_float(XDR *, float *);
int xdr_double(XDR *, double *);
int xdr_enum(XDR *, enum_t *);

/* Memory-based XDR stream creation */
void xdrmem_create(XDR *, char *, u_int, enum xdr_op);

/* Utility functions */
u_int xdr_sizeof(xdrproc_t, void *);
void xdr_free(xdrproc_t, void *);

#endif /* !_RPC_XDR_H_ */