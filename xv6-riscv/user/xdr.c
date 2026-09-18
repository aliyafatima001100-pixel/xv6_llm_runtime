#include "../kernel/types.h"
#include "user.h"
#include "xdr.h"

/* Memory-based XDR stream private data */
typedef struct {
    char *buf;          /* buffer base */
    char *ptr;          /* current position */
    char *end;          /* buffer end */
    enum xdr_op op;     /* encode/decode/free */
} xdrmem_private;

/* Forward declarations */
static int xdrmem_getlong(XDR *, long *);
static int xdrmem_putlong(XDR *, long *);
static int xdrmem_getbytes(XDR *, char *, u_int);
static int xdrmem_putbytes(XDR *, char *, u_int);
static u_int xdrmem_getpos(XDR *);
static int xdrmem_setpos(XDR *, u_int);
static long *xdrmem_inline(XDR *, int);
static void xdrmem_destroy(XDR *);

static struct xdr_ops xdrmem_ops = {
    .x_getlong = xdrmem_getlong,
    .x_putlong = xdrmem_putlong,
    .x_getbytes = xdrmem_getbytes,
    .x_putbytes = xdrmem_putbytes,
    .x_getpos = xdrmem_getpos,
    .x_setpos = xdrmem_setpos,
    .x_inline = xdrmem_inline,
    .x_destroy = xdrmem_destroy
};

/* ==============================================
 * Memory Stream Implementation
 * ============================================== */

static int
xdrmem_getlong(XDR *xdrs, long *lp)
{
    xdrmem_private *priv = (xdrmem_private *)xdrs->x_private;
    
    if (priv->ptr + 4 > priv->end)
        return 0;
    
    /* Network byte order (big-endian) */
    *lp = ((long)(unsigned char)priv->ptr[0] << 24) |
          ((long)(unsigned char)priv->ptr[1] << 16) |
          ((long)(unsigned char)priv->ptr[2] << 8) |
          ((long)(unsigned char)priv->ptr[3]);
    
    priv->ptr += 4;
    return 1;
}

static int
xdrmem_putlong(XDR *xdrs, long *lp)
{
    xdrmem_private *priv = (xdrmem_private *)xdrs->x_private;
    
    if (priv->ptr + 4 > priv->end)
        return 0;
    
    /* Network byte order (big-endian) */
    priv->ptr[0] = (char)((*lp >> 24) & 0xff);
    priv->ptr[1] = (char)((*lp >> 16) & 0xff);
    priv->ptr[2] = (char)((*lp >> 8) & 0xff);
    priv->ptr[3] = (char)(*lp & 0xff);
    
    priv->ptr += 4;
    return 1;
}

static int
xdrmem_getbytes(XDR *xdrs, char *addr, u_int len)
{
    xdrmem_private *priv = (xdrmem_private *)xdrs->x_private;
    
    if (priv->ptr + len > priv->end)
        return 0;
    
    memmove(addr, priv->ptr, len);
    priv->ptr += len;
    return 1;
}

static int
xdrmem_putbytes(XDR *xdrs, char *addr, u_int len)
{
    xdrmem_private *priv = (xdrmem_private *)xdrs->x_private;
    
    if (priv->ptr + len > priv->end)
        return 0;
    
    memmove(priv->ptr, addr, len);
    priv->ptr += len;
    return 1;
}

static u_int
xdrmem_getpos(XDR *xdrs)
{
    xdrmem_private *priv = (xdrmem_private *)xdrs->x_private;
    return (u_int)(priv->ptr - priv->buf);
}

static int
xdrmem_setpos(XDR *xdrs, u_int pos)
{
    xdrmem_private *priv = (xdrmem_private *)xdrs->x_private;
    char *newptr = priv->buf + pos;
    
    if (newptr < priv->buf || newptr > priv->end)
        return 0;
    
    priv->ptr = newptr;
    return 1;
}

static long *
xdrmem_inline(XDR *xdrs, int len)
{
    xdrmem_private *priv = (xdrmem_private *)xdrs->x_private;
    long *buf = 0;
    
    if (priv->ptr + len <= priv->end) {
        buf = (long *)priv->ptr;
        priv->ptr += len;
    }
    return buf;
}

static void
xdrmem_destroy(XDR *xdrs)
{
    xdrmem_private *priv = (xdrmem_private *)xdrs->x_private;
    if (priv) {
        free((char *)priv);
    }
}

void
xdrmem_create(XDR *xdrs, char *addr, u_int size, enum xdr_op op)
{
    xdrmem_private *priv;
    
    priv = (xdrmem_private *)malloc(sizeof(xdrmem_private));
    if (!priv)
        return;
    
    priv->buf = addr;
    priv->ptr = addr;
    priv->end = addr + size;
    priv->op = op;
    
    xdrs->x_op = op;
    xdrs->x_ops = &xdrmem_ops;
    xdrs->x_private = (char *)priv;
    xdrs->x_base = 0;
    xdrs->x_handy = 0;
}

/* ==============================================
 * Primitive XDR Routines
 * ============================================== */

int
xdr_void(void)
{
    return 1;
}

int
xdr_bool(XDR *xdrs, bool_t *bp)
{
    long l;
    
    switch (xdrs->x_op) {
    case XDR_ENCODE:
        l = *bp ? 1 : 0;
        return ((*xdrs->x_ops->x_putlong)(xdrs, &l));
    case XDR_DECODE:
        if (!(*xdrs->x_ops->x_getlong)(xdrs, &l))
            return 0;
        *bp = (l != 0);
        return 1;
    case XDR_FREE:
        return 1;
    }
    return 0;
}

int
xdr_char(XDR *xdrs, char *cp)
{
    long l;
    
    switch (xdrs->x_op) {
    case XDR_ENCODE:
        l = (unsigned char)*cp;
        return ((*xdrs->x_ops->x_putlong)(xdrs, &l));
    case XDR_DECODE:
        if (!(*xdrs->x_ops->x_getlong)(xdrs, &l))
            return 0;
        *cp = (char)l;
        return 1;
    case XDR_FREE:
        return 1;
    }
    return 0;
}

int
xdr_u_char(XDR *xdrs, u_char *cp)
{
    long l;
    
    switch (xdrs->x_op) {
    case XDR_ENCODE:
        l = (long)*cp;
        return ((*xdrs->x_ops->x_putlong)(xdrs, &l));
    case XDR_DECODE:
        if (!(*xdrs->x_ops->x_getlong)(xdrs, &l))
            return 0;
        *cp = (u_char)l;
        return 1;
    case XDR_FREE:
        return 1;
    }
    return 0;
}

int
xdr_short(XDR *xdrs, short *sp)
{
    long l;
    
    switch (xdrs->x_op) {
    case XDR_ENCODE:
        l = (long)*sp;
        return ((*xdrs->x_ops->x_putlong)(xdrs, &l));
    case XDR_DECODE:
        if (!(*xdrs->x_ops->x_getlong)(xdrs, &l))
            return 0;
        *sp = (short)l;
        return 1;
    case XDR_FREE:
        return 1;
    }
    return 0;
}

int
xdr_u_short(XDR *xdrs, u_short *usp)
{
    long l;
    
    switch (xdrs->x_op) {
    case XDR_ENCODE:
        l = (long)*usp;
        return ((*xdrs->x_ops->x_putlong)(xdrs, &l));
    case XDR_DECODE:
        if (!(*xdrs->x_ops->x_getlong)(xdrs, &l))
            return 0;
        *usp = (u_short)l;
        return 1;
    case XDR_FREE:
        return 1;
    }
    return 0;
}

int
xdr_int(XDR *xdrs, int *ip)
{
    long l;
    
    switch (xdrs->x_op) {
    case XDR_ENCODE:
        l = (long)*ip;
        return ((*xdrs->x_ops->x_putlong)(xdrs, &l));
    case XDR_DECODE:
        if (!(*xdrs->x_ops->x_getlong)(xdrs, &l))
            return 0;
        *ip = (int)l;
        return 1;
    case XDR_FREE:
        return 1;
    }
    return 0;
}

int
xdr_u_int(XDR *xdrs, u_int *up)
{
    long l;
    
    switch (xdrs->x_op) {
    case XDR_ENCODE:
        l = (long)*up;
        return ((*xdrs->x_ops->x_putlong)(xdrs, &l));
    case XDR_DECODE:
        if (!(*xdrs->x_ops->x_getlong)(xdrs, &l))
            return 0;
        *up = (u_int)l;
        return 1;
    case XDR_FREE:
        return 1;
    }
    return 0;
}

int
xdr_long(XDR *xdrs, long *lp)
{
    switch (xdrs->x_op) {
    case XDR_ENCODE:
        return ((*xdrs->x_ops->x_putlong)(xdrs, lp));
    case XDR_DECODE:
        return ((*xdrs->x_ops->x_getlong)(xdrs, lp));
    case XDR_FREE:
        return 1;
    }
    return 0;
}

int
xdr_u_long(XDR *xdrs, u_long *ulp)
{
    switch (xdrs->x_op) {
    case XDR_ENCODE:
        return ((*xdrs->x_ops->x_putlong)(xdrs, (long *)ulp));
    case XDR_DECODE:
        return ((*xdrs->x_ops->x_getlong)(xdrs, (long *)ulp));
    case XDR_FREE:
        return 1;
    }
    return 0;
}

int
xdr_hyper(XDR *xdrs, quad_t *llp)
{
    long t[2];
    
    switch (xdrs->x_op) {
    case XDR_ENCODE:
        /* Split 64-bit into two 32-bit values */
        t[0] = (long)(*llp >> 32);
        t[1] = (long)*llp;
        if (!(*xdrs->x_ops->x_putlong)(xdrs, &t[0]))
            return 0;
        return ((*xdrs->x_ops->x_putlong)(xdrs, &t[1]));
    case XDR_DECODE:
        if (!(*xdrs->x_ops->x_getlong)(xdrs, &t[0]))
            return 0;
        if (!(*xdrs->x_ops->x_getlong)(xdrs, &t[1]))
            return 0;
        *llp = ((quad_t)t[0] << 32) | ((quad_t)t[1] & 0xffffffffUL);
        return 1;
    case XDR_FREE:
        return 1;
    }
    return 0;
}

int
xdr_u_hyper(XDR *xdrs, u_quad_t *ullp)
{
    return xdr_hyper(xdrs, (quad_t *)ullp);
}

int
xdr_float(XDR *xdrs, float *fp)
{
    long l;
    
    switch (xdrs->x_op) {
    case XDR_ENCODE:
        /* Treat float bits as long */
        l = *(long *)fp;
        return ((*xdrs->x_ops->x_putlong)(xdrs, &l));
    case XDR_DECODE:
        if (!(*xdrs->x_ops->x_getlong)(xdrs, &l))
            return 0;
        *(long *)fp = l;
        return 1;
    case XDR_FREE:
        return 1;
    }
    return 0;
}

int
xdr_double(XDR *xdrs, double *dp)
{
    long t[2];
    
    switch (xdrs->x_op) {
    case XDR_ENCODE:
        /* Treat double bits as two longs */
        t[0] = ((long *)dp)[0];
        t[1] = ((long *)dp)[1];
        if (!(*xdrs->x_ops->x_putlong)(xdrs, &t[0]))
            return 0;
        return ((*xdrs->x_ops->x_putlong)(xdrs, &t[1]));
    case XDR_DECODE:
        if (!(*xdrs->x_ops->x_getlong)(xdrs, &t[0]))
            return 0;
        if (!(*xdrs->x_ops->x_getlong)(xdrs, &t[1]))
            return 0;
        ((long *)dp)[0] = t[0];
        ((long *)dp)[1] = t[1];
        return 1;
    case XDR_FREE:
        return 1;
    }
    return 0;
}

int
xdr_enum(XDR *xdrs, enum_t *ep)
{
    long l;
    
    switch (xdrs->x_op) {
    case XDR_ENCODE:
        l = (long)*ep;
        return ((*xdrs->x_ops->x_putlong)(xdrs, &l));
    case XDR_DECODE:
        if (!(*xdrs->x_ops->x_getlong)(xdrs, &l))
            return 0;
        *ep = (enum_t)l;
        return 1;
    case XDR_FREE:
        return 1;
    }
    return 0;
}

/* ==============================================
 * Utility Functions
 * ============================================== */

u_int
xdr_sizeof(xdrproc_t func, void *data)
{
    XDR x;
    char buf[4096];
    
    xdrmem_create(&x, buf, sizeof(buf), XDR_ENCODE);
    if (!func(&x, data)) {
        return 0;
    }
    return XDR_GETPOS(&x);
}

void
xdr_free(xdrproc_t proc, void *objp)
{
    XDR x;
    xdrmem_create(&x, 0, 0, XDR_FREE);
    (*proc)(&x, objp);
    XDR_DESTROY(&x);
}