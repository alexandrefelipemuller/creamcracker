#define false 1==0

/****************
 * Rotate a 32 bit integer by n bytes
 */
#if defined(__GNUC__) && defined(__i386__)
inline unsigned int ROTATE_LEFT( unsigned int x, int n)
{
	__asm__("roll %%cl,%0"
			:"=r" (x)
			:"0" (x),"c" (n));
	return x;
}
#else
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))
#endif

#define ROTATE_RIGHT(x,n) (((x) >> (n)) | ((x) << (32-(n))))

