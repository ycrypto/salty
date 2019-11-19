typedef unsigned int fe25519[8];

void fe25519_mul_asm (fe25519 *pResult, const fe25519 *pVal1, const fe25519 *pVal2);
void fe25519_square_asm (fe25519 *pResult, const fe25519 *pVal);
