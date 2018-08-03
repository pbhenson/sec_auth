#ifndef SAMBA_H
#define SAMBA_H

void samba_E_P24(unsigned char *p21, unsigned char *c8, unsigned char *p24);
void samba_nt_lm_owf_gen(char *pwd, unsigned char nt_p16[16], unsigned char p16[16]);

#endif
