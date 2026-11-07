/* the host stub test: libnix's constructor lists are not run on the host */
#define ADD2INIT(f, p) static void (*const f##_list)(void) __attribute__((used)) = f
#define ADD2EXIT(f, p) static void (*const f##_list)(void) __attribute__((used)) = f
