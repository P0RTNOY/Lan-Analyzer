#include "types.h"
volatile u8 tmp[6]; int main() { printf("%d\n", *(u32*)(tmp+1)); return 0; }
