#include "../kernel/types.h"
#include "user.h"
#include "xdr.h"

/* Example RPC request structure */
typedef struct {
    int request_id;
    int operation;
    long value;
} rpc_request_t;

/* XDR procedure for serializing/deserializing rpc_request */
int
xdr_rpc_request(XDR *xdrs, rpc_request_t *req)
{
    if (!xdr_int(xdrs, &req->request_id))
        return 0;
    if (!xdr_int(xdrs, &req->operation))
        return 0;
    if (!xdr_long(xdrs, &req->value))
        return 0;
    return 1;
}

int
main(void)
{
    char buf[256];
    XDR xdrs;
    rpc_request_t req1, req2;
    int pos;
    
    printf("XDR Library Test\n");
    printf("================\n\n");
    
    /* Initialize request */
    req1.request_id = 42;
    req1.operation = 7;
    req1.value = 12345L;
    
    printf("Original request:\n");
    printf("  request_id: %d\n", req1.request_id);
    printf("  operation: %d\n", req1.operation);
    printf("  value: %ld\n\n", req1.value);
    
    /* Encode */
    xdrmem_create(&xdrs, buf, sizeof(buf), XDR_ENCODE);
    if (!xdr_rpc_request(&xdrs, &req1)) {
        printf("Encoding failed!\n");
        return 1;
    }
    pos = XDR_GETPOS(&xdrs);
    printf("Encoded %d bytes\n\n", pos);
    XDR_DESTROY(&xdrs);
    
    /* Decode */
    xdrmem_create(&xdrs, buf, sizeof(buf), XDR_DECODE);
    if (!xdr_rpc_request(&xdrs, &req2)) {
        printf("Decoding failed!\n");
        return 1;
    }
    XDR_DESTROY(&xdrs);
    
    printf("Decoded request:\n");
    printf("  request_id: %d\n", req2.request_id);
    printf("  operation: %d\n", req2.operation);
    printf("  value: %ld\n\n", req2.value);
    
    /* Verify */
    if (req1.request_id == req2.request_id &&
        req1.operation == req2.operation &&
        req1.value == req2.value) {
        printf("✓ Test PASSED - serialization round-trip successful!\n");
        return 0;
    } else {
        printf("✗ Test FAILED - data mismatch!\n");
        return 1;
    }
}