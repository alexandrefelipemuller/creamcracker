#define false 1==0

/* ROTATE_LEFT rotates x left n bits */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

#define ROTATE_RIGHT(x,n) (((x) >> (n)) | ((x) << (32-(n))))
