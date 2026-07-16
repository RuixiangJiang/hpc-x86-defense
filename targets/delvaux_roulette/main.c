#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "api.h"
#include "params.h"
#include "roulette_masked_invntt_x86.h"
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define KEY_MAGIC "ROU4K768"
#define KEY_MAGIC_LEN 8u

typedef struct { char magic[KEY_MAGIC_LEN]; uint64_t pk_len; uint64_t sk_len; } key_header;
typedef enum { F_INVALID=0, F_SKIP, F_CONSTANT, F_RANDOM, F_FLIP } family_t;
typedef enum { M_UNSET=0, M_BASELINE, M_ATTACK } rou_case_mode_t;
typedef struct { family_t family; rou_case_mode_t mode; const char *label; unsigned int runtime_mode; } case_t;

static unsigned long parse_ulong(const char *text, const char *name) {
    char *end = NULL; unsigned long value;
    errno = 0; value = strtoul(text, &end, 0);
    if (errno != 0 || end == text || *end != '\0') {
        fprintf(stderr, "[error] invalid %s: %s\n", name, text); exit(EXIT_FAILURE);
    }
    return value;
}
static long parse_long(const char *text, const char *name) {
    char *end = NULL; long value;
    errno = 0; value = strtol(text, &end, 0);
    if (errno != 0 || end == text || *end != '\0') {
        fprintf(stderr, "[error] invalid %s: %s\n", name, text); exit(EXIT_FAILURE);
    }
    return value;
}
static int bind_to_cpu(int cpu) {
    cpu_set_t set;
    if (cpu < 0 || cpu >= CPU_SETSIZE) { errno = EINVAL; return -1; }
    CPU_ZERO(&set); CPU_SET((unsigned int)cpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0) return -1;
    if (sched_getcpu() != cpu) { errno = EXDEV; return -1; }
    return 0;
}
static int write_all(int fd, const void *buf, size_t len) {
    const uint8_t *p = buf;
    while (len > 0u) {
        ssize_t n = write(fd, p, len);
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        p += (size_t)n; len -= (size_t)n;
    }
    return 0;
}
static int read_all(int fd, void *buf, size_t len) {
    uint8_t *p = buf;
    while (len > 0u) {
        ssize_t n = read(fd, p, len);
        if (n == 0) { errno = EIO; return -1; }
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        p += (size_t)n; len -= (size_t)n;
    }
    return 0;
}
static int save_key_file(const char *path, const uint8_t *pk, const uint8_t *sk) {
    key_header hdr; int fd;
    memcpy(hdr.magic, KEY_MAGIC, KEY_MAGIC_LEN);
    hdr.pk_len = PQCLEAN_KYBER768_CLEAN_CRYPTO_PUBLICKEYBYTES;
    hdr.sk_len = PQCLEAN_KYBER768_CLEAN_CRYPTO_SECRETKEYBYTES;
    fd = open(path, O_WRONLY|O_CREAT|O_TRUNC, S_IRUSR|S_IWUSR);
    if (fd < 0) return -1;
    if (write_all(fd,&hdr,sizeof(hdr)) != 0 ||
        write_all(fd,pk,PQCLEAN_KYBER768_CLEAN_CRYPTO_PUBLICKEYBYTES) != 0 ||
        write_all(fd,sk,PQCLEAN_KYBER768_CLEAN_CRYPTO_SECRETKEYBYTES) != 0) {
        int saved=errno; close(fd); errno=saved; return -1;
    }
    return close(fd);
}
static int load_key_file(const char *path, uint8_t *pk, uint8_t *sk) {
    key_header hdr; int fd=open(path,O_RDONLY);
    if (fd < 0) return -1;
    if (read_all(fd,&hdr,sizeof(hdr)) != 0 ||
        memcmp(hdr.magic,KEY_MAGIC,KEY_MAGIC_LEN) != 0 ||
        hdr.pk_len != PQCLEAN_KYBER768_CLEAN_CRYPTO_PUBLICKEYBYTES ||
        hdr.sk_len != PQCLEAN_KYBER768_CLEAN_CRYPTO_SECRETKEYBYTES ||
        read_all(fd,pk,PQCLEAN_KYBER768_CLEAN_CRYPTO_PUBLICKEYBYTES) != 0 ||
        read_all(fd,sk,PQCLEAN_KYBER768_CLEAN_CRYPTO_SECRETKEYBYTES) != 0) {
        int saved=errno!=0?errno:EINVAL; close(fd); errno=saved; return -1;
    }
    return close(fd);
}
static uint8_t get_v_symbol(const uint8_t ct[KYBER_CIPHERTEXTBYTES], unsigned int target) {
    size_t offset=(size_t)KYBER_POLYVECCOMPRESSEDBYTES+(size_t)(target>>1);
    unsigned int shift=(target&1u)*4u;
    return (uint8_t)((ct[offset]>>shift)&0x0fu);
}
static void manipulate_v_symbol(uint8_t ct[KYBER_CIPHERTEXTBYTES], unsigned int target) {
    size_t offset=(size_t)KYBER_POLYVECCOMPRESSEDBYTES+(size_t)(target>>1);
    unsigned int shift=(target&1u)*4u;
    uint8_t mask=(uint8_t)(0x0fu<<shift);
    uint8_t old_symbol=(uint8_t)((ct[offset]>>shift)&0x0fu);
    uint8_t new_symbol=(uint8_t)((old_symbol+4u)&0x0fu);
    ct[offset]=(uint8_t)((ct[offset]&(uint8_t)~mask)|(uint8_t)(new_symbol<<shift));
}
static uint32_t sample_seed(uint64_t domain, unsigned long sample, uint32_t salt) {
    uint64_t z=domain^((uint64_t)(sample+1u)*UINT64_C(0x9e3779b97f4a7c15))^(uint64_t)salt;
    z=(z^(z>>30))*UINT64_C(0xbf58476d1ce4e5b9);
    z=(z^(z>>27))*UINT64_C(0x94d049bb133111eb); z^=z>>31;
    return (uint32_t)z != 0u ? (uint32_t)z : (salt|1u);
}
static family_t parse_family(const char *label) {
    if (strcmp(label,"skip-local-masked-operation")==0) return F_SKIP;
    if (strcmp(label,"set-masked-intermediate-constant")==0) return F_CONSTANT;
    if (strcmp(label,"replace-masked-intermediate-random")==0) return F_RANDOM;
    if (strcmp(label,"flip-masked-intermediate-bit")==0) return F_FLIP;
    return F_INVALID;
}
static case_t prepare_case(const char *label, rou_case_mode_t mode) {
    case_t c; memset(&c,0,sizeof(c)); c.family=parse_family(label); c.mode=mode; c.label=label;
    if (mode==M_BASELINE) { c.runtime_mode=ROU_MODE_BASELINE; return c; }
    switch(c.family) {
    case F_SKIP: c.runtime_mode=ROU_MODE_SKIP_LOCAL_OPERATION; break;
    case F_CONSTANT: c.runtime_mode=ROU_MODE_SET_CONSTANT; break;
    case F_RANDOM: c.runtime_mode=ROU_MODE_SET_RANDOM; break;
    case F_FLIP: c.runtime_mode=ROU_MODE_FLIP_BIT; break;
    default: c.runtime_mode=UINT32_MAX; break;
    }
    return c;
}
static const char *target_kind(family_t f) {
    return f==F_SKIP ? "masked-intt-local-operation" : "masked-intt-data-intermediate";
}
static int semantic_valid_for_case(const case_t *c, const rou_audit_snapshot *a) {
    int32_t expected;
    if (!a->valid || !a->compare_recorded || a->mode!=c->runtime_mode || a->non_target_mismatches!=0u) return 0;
    switch(c->runtime_mode) {
    case ROU_MODE_BASELINE:
        expected=a->normal_intermediate;
        return a->fault_applied==0u && a->used_intermediate==expected && a->target_changed==0u;
    case ROU_MODE_SKIP_LOCAL_OPERATION:
        expected=a->share_a_before;
        return a->operation_skipped==1u && a->used_intermediate==expected;
    case ROU_MODE_SET_CONSTANT:
        expected=a->selected_constant;
        return a->constant_replacement==1u && a->used_intermediate==expected;
    case ROU_MODE_SET_RANDOM:
        expected=a->selected_random;
        return a->random_replacement==1u && a->used_intermediate==expected;
    case ROU_MODE_FLIP_BIT:
        expected=a->normal_intermediate^(int32_t)a->flip_mask;
        return a->bit_flipped==1u && a->used_intermediate==expected;
    default: return 0;
    }
}
static int run_one(const case_t *c, uint8_t *ct0, uint8_t *ct1, uint8_t *ss0, uint8_t *ss1,
                   const uint8_t *pk, const uint8_t *sk, unsigned int target,
                   uint64_t domain, unsigned long sample, int measured,
                   uint8_t *orig, uint8_t *manip, rou_audit_snapshot *audit) {
    int er=PQCLEAN_KYBER768_CLEAN_crypto_kem_enc(ct0,ss0,pk); int dr;
    if (er!=0) return 0;
    memcpy(ct1,ct0,PQCLEAN_KYBER768_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    *orig=get_v_symbol(ct1,target); manipulate_v_symbol(ct1,target); *manip=get_v_symbol(ct1,target);
    PQCLEAN_KYBER768_CLEAN_roulette_set_mask_seed(sample_seed(domain,sample,UINT32_C(0x4d41534b)));
    PQCLEAN_KYBER768_CLEAN_roulette_set_fault_seed(sample_seed(domain,sample,UINT32_C(0x4641554c)));
    PQCLEAN_KYBER768_CLEAN_roulette_set_measurement_enabled(measured);
    dr=PQCLEAN_KYBER768_CLEAN_crypto_kem_dec(ss1,ct1,sk);
    PQCLEAN_KYBER768_CLEAN_roulette_set_measurement_enabled(0);
    PQCLEAN_KYBER768_CLEAN_roulette_get_audit_snapshot(audit);
    return dr==0 && *manip==(uint8_t)((*orig+4u)&0x0fu) &&
           audit->input_v_symbol==*manip && semantic_valid_for_case(c,audit);
}
static void write_header(FILE *out) {
    unsigned int i;
    fputs("sample,family,mode,is_attack,input_domain,semantic_valid,fault_applied,differs_intended,"
          "target_kind,target_coeff,mask_seed,fault_seed,selected_constant,selected_random,flip_bit,flip_mask,"
          "share_a_before,share_b_before,normal_intermediate,used_intermediate,reference_coeff_mod_q,"
          "observed_coeff_mod_q,target_changed,non_target_mismatches,operation_skipped,constant_replacement,"
          "random_replacement,bit_flipped,original_v_symbol,manipulated_v_symbol,reencrypted_v_symbol,"
          "target_symbol_match,compare_fail,oracle_success,intended_output_tag,output_tag,affinity_cpu,"
          "cpu_before,cpu_after,cpu_stable,sequence,time_enabled,time_running,running_percent,requested_mask,"
          "available_mask,open_error_mask,valid_mask,error_code",out);
    for(i=0;i<ROU_HPC_EVENT_COUNT;++i) fprintf(out,",%s",rou_event_name(i));
    fputc('\n',out);
}

int main(int argc,char **argv) {
    const char *output=NULL,*key_path=NULL,*family_label=NULL;
    unsigned long samples=500u,warmup=20u,target=17u,counter_set=1u,domain=UINT64_C(0x524f5531),flip_bit=5u;
    long constant=INT32_C(0x5a5a);
    int cpu=-1,create_key=0,self_test=0; rou_case_mode_t mode=M_UNSET; case_t c;
    uint8_t *pk=NULL,*sk=NULL,*ct0=NULL,*ct1=NULL;
    uint8_t ss0[PQCLEAN_KYBER768_CLEAN_CRYPTO_BYTES],ss1[PQCLEAN_KYBER768_CLEAN_CRYPTO_BYTES];
    FILE *out=NULL; unsigned long i; int ret=EXIT_FAILURE;
    for(i=1;i<(unsigned long)argc;++i) {
        if(strcmp(argv[i],"--samples")==0&&i+1<(unsigned long)argc) samples=parse_ulong(argv[++i],"samples");
        else if(strcmp(argv[i],"--warmup")==0&&i+1<(unsigned long)argc) warmup=parse_ulong(argv[++i],"warmup");
        else if(strcmp(argv[i],"--target-coeff")==0&&i+1<(unsigned long)argc) target=parse_ulong(argv[++i],"target");
        else if(strcmp(argv[i],"--counter-set")==0&&i+1<(unsigned long)argc) counter_set=parse_ulong(argv[++i],"counter set");
        else if(strcmp(argv[i],"--domain")==0&&i+1<(unsigned long)argc) domain=parse_ulong(argv[++i],"domain");
        else if(strcmp(argv[i],"--constant")==0&&i+1<(unsigned long)argc) constant=parse_long(argv[++i],"constant");
        else if(strcmp(argv[i],"--flip-bit")==0&&i+1<(unsigned long)argc) flip_bit=parse_ulong(argv[++i],"flip bit");
        else if(strcmp(argv[i],"--cpu")==0&&i+1<(unsigned long)argc) cpu=(int)parse_ulong(argv[++i],"CPU");
        else if(strcmp(argv[i],"--output")==0&&i+1<(unsigned long)argc) output=argv[++i];
        else if(strcmp(argv[i],"--key-file")==0&&i+1<(unsigned long)argc) key_path=argv[++i];
        else if(strcmp(argv[i],"--family-label")==0&&i+1<(unsigned long)argc) family_label=argv[++i];
        else if(strcmp(argv[i],"--mode")==0&&i+1<(unsigned long)argc) {
            const char *m=argv[++i]; if(strcmp(m,"baseline")==0) mode=M_BASELINE;
            else if(strcmp(m,"attack")==0) mode=M_ATTACK; else goto cleanup;
        } else if(strcmp(argv[i],"--create-key")==0) create_key=1;
        else if(strcmp(argv[i],"--self-test")==0) self_test=1;
        else { fprintf(stderr,"[error] unknown argument: %s\n",argv[i]); goto cleanup; }
    }
    if(family_label==NULL||mode==M_UNSET) goto cleanup;
    c=prepare_case(family_label,mode);
    if(c.family==F_INVALID||c.runtime_mode==UINT32_MAX||target>=128u||flip_bit>=16u||
       constant<INT16_MIN||constant>INT16_MAX||rou_select_counter_set((unsigned int)counter_set)!=0) goto cleanup;
    if(PQCLEAN_KYBER768_CLEAN_roulette_set_mode(c.runtime_mode)!=0||
       PQCLEAN_KYBER768_CLEAN_roulette_set_flip_bit((unsigned int)flip_bit)!=0) goto cleanup;
    PQCLEAN_KYBER768_CLEAN_roulette_set_target((unsigned int)target);
    PQCLEAN_KYBER768_CLEAN_roulette_set_constant((int32_t)constant);
    pk=malloc(PQCLEAN_KYBER768_CLEAN_CRYPTO_PUBLICKEYBYTES);
    sk=malloc(PQCLEAN_KYBER768_CLEAN_CRYPTO_SECRETKEYBYTES);
    ct0=malloc(PQCLEAN_KYBER768_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    ct1=malloc(PQCLEAN_KYBER768_CLEAN_CRYPTO_CIPHERTEXTBYTES);
    if(!pk||!sk||!ct0||!ct1) goto cleanup;
    if(self_test) {
        if(PQCLEAN_KYBER768_CLEAN_crypto_kem_keypair(pk,sk)!=0) goto cleanup;
        for(i=0;i<32u;++i) {
            uint8_t o,m; rou_audit_snapshot a;
            if(!run_one(&c,ct0,ct1,ss0,ss1,pk,sk,(unsigned int)target,UINT64_C(0x53454d414e544943),i,0,&o,&m,&a)) goto cleanup;
        }
        printf("semantic self-test passed: family=%s mode=%s cases=32\n",family_label,PQCLEAN_KYBER768_CLEAN_roulette_mode_name());
        ret=EXIT_SUCCESS; goto cleanup;
    }
    if(!output||!key_path||samples==0u||cpu<0||bind_to_cpu(cpu)!=0) goto cleanup;
    if(create_key) {
        if(PQCLEAN_KYBER768_CLEAN_crypto_kem_keypair(pk,sk)!=0||save_key_file(key_path,pk,sk)!=0) goto cleanup;
    } else if(load_key_file(key_path,pk,sk)!=0) goto cleanup;
    for(i=0;i<warmup;++i) {
        uint8_t o,m; rou_audit_snapshot a;
        if(!run_one(&c,ct0,ct1,ss0,ss1,pk,sk,(unsigned int)target,(uint64_t)domain^UINT64_C(0x5741524d),i,0,&o,&m,&a)) goto cleanup;
    }
    if(rou_hpc_init()!=0) goto cleanup;
    out=fopen(output,"w"); if(!out) goto cleanup; write_header(out);
    for(i=0;i<samples;++i) {
        uint8_t o,m; rou_audit_snapshot a; rou_hpc_snapshot s;
        uint32_t mask_seed=sample_seed((uint64_t)domain,i,UINT32_C(0x4d41534b));
        uint32_t fault_seed=sample_seed((uint64_t)domain,i,UINT32_C(0x4641554c));
        int before=sched_getcpu(); int sem=run_one(&c,ct0,ct1,ss0,ss1,pk,sk,(unsigned int)target,(uint64_t)domain,i,1,&o,&m,&a);
        int after=sched_getcpu(); int stable=before==cpu&&after==cpu; int differs=a.used_intermediate!=a.normal_intermediate;
        double pct; unsigned int e; rou_get_hpc_snapshot(&s);
        pct=s.time_enabled==0u?0.0:100.0*(double)s.time_running/(double)s.time_enabled;
        fprintf(out,"%lu,%s,%s,%d,0x%016" PRIx64 ",%d,%u,%d,%s,%lu,0x%08" PRIx32 ",0x%08" PRIx32 ","
                    "%" PRId32 ",%" PRId32 ",%u,0x%08" PRIx32 ",%" PRId32 ",%" PRId32 ",%" PRId32 ",%" PRId32 ","
                    "%" PRId32 ",%" PRId32 ",%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,0x%016" PRIx64 ",0x%016" PRIx64 ","
                    "%d,%d,%d,%d,%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%.6f,0x%08" PRIx32 ",0x%08" PRIx32 ",0x%08" PRIx32 ",0x%08" PRIx32 ",%" PRId32,
                    i,family_label,mode==M_ATTACK?family_label:"canonical-baseline",mode==M_ATTACK,(uint64_t)domain,sem,a.fault_applied,differs,
                    target_kind(c.family),target,mask_seed,fault_seed,a.selected_constant,a.selected_random,a.flip_bit,a.flip_mask,a.share_a_before,a.share_b_before,
                    a.normal_intermediate,a.used_intermediate,a.reference_coeff_mod_q,a.observed_coeff_mod_q,a.target_changed,a.non_target_mismatches,
                    a.operation_skipped,a.constant_replacement,a.random_replacement,a.bit_flipped,o,m,a.reencrypted_v_symbol,a.target_symbol_match,a.compare_fail,
                    a.oracle_success,a.reference_output_tag,a.observed_output_tag,cpu,before,after,stable,s.sequence,s.time_enabled,s.time_running,pct,
                    s.requested_mask,s.available_mask,s.open_error_mask,s.valid_mask,s.error_code);
        for(e=0;e<ROU_HPC_EVENT_COUNT;++e) fprintf(out,",%" PRIu64,s.values[e]);
        fputc('\n',out);
        if(!sem||!stable||s.error_code!=0) goto cleanup;
    }
    fflush(out); ret=EXIT_SUCCESS;
cleanup:
    PQCLEAN_KYBER768_CLEAN_roulette_set_measurement_enabled(0);
    PQCLEAN_KYBER768_CLEAN_roulette_set_reencrypt_active(0);
    rou_hpc_close(); if(out) fclose(out); free(ct1); free(ct0); free(sk); free(pk); return ret;
}
