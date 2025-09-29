/* giftcardreader.c
 * Hardened version w/ optional FIXES compilation flag.
 *
 * Build vulnerable original:
 *   gcc -Wall -g -o giftcardreader.original giftcardreader.c
 *
 * Build fixed:
 *   gcc -Wall -g -DFIXES -o giftcardreader giftcardreader.c
 */

#include "giftcard.h"

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <limits.h>
#include <stdint.h>
#include <errno.h>

/* Tunable safety limits for FIXES mode */
#ifndef MAX_SAFE_ALLOC
#define MAX_SAFE_ALLOC (16 * 1024 * 1024) /* 16 MB */
#endif

#ifndef MAX_ANIM_STEPS
#define MAX_ANIM_STEPS 1000000U
#endif

/* --- Helper functions used in FIXES mode --- */
#ifdef FIXES
static void *safe_malloc(size_t n) {
    if (n == 0 || n > MAX_SAFE_ALLOC) {
        fprintf(stderr, "safe_malloc: refusing to allocate %zu bytes\n", n);
        return NULL;
    }
    void *p = malloc(n);
    if (!p) {
        perror("malloc");
    }
    return p;
}

/* Reads exactly `size` bytes or returns -1 on error/short-read */
static int safe_fread_exact(void *buf, size_t size, FILE *f) {
    if (size == 0) return 0;
    size_t got = fread(buf, 1, size, f);
    if (got != size) {
        if (feof(f)) {
            fprintf(stderr, "safe_fread_exact: unexpected EOF (wanted %zu got %zu)\n", size, got);
        } else {
            perror("fread");
        }
        return -1;
    }
    return 0;
}

/* Safe addition check to avoid wrap-around */
static int checked_add_size(size_t a, size_t b, size_t *out) {
    if (a > SIZE_MAX - b) return -1;
    *out = a + b;
    return 0;
}
#endif /* FIXES */

/* Interpreter for THX-1138 assembly */
void animate(char *msg, unsigned char *program) {
    unsigned char regs[16];
    char *mptr = msg;
    unsigned char *pc = program;

#ifndef FIXES
    int i = 0;
    int zf = 0;
    while (1) {
        unsigned char op, arg1, arg2;
        op = *pc;
        arg1 = *(pc+1);
        arg2 = *(pc+2);
        switch (*pc) {
            case 0x00:
                break;
            case 0x01:
                if (arg1 < 16) {
                    regs[arg1] = *mptr;
                }
                break;
            case 0x02:
                *mptr = regs[arg1];
                break;
            case 0x03:
                mptr += (char)arg1;
                break;
            case 0x04:
                if ((arg1 < 16) && (arg2 < 16)) {
                    regs[arg2] = arg1;
                }
                break;
            case 0x05:
                regs[arg1] ^= regs[arg2];
                zf = !regs[arg1];
                break;
            case 0x06:
                regs[arg1] += regs[arg2];
                zf = !regs[arg1];
                break;
            case 0x07:
                puts(msg);
                break;
            case 0x08:
                goto done;
            case 0x09:
                pc += (unsigned char)arg1;
                break;
            case 0x10:
                if (zf) pc += (unsigned char)arg1;
                break;
        }
        pc += 3;
        if (pc > program + 256) break;
    }
done:
    return;
#else
    /* FIXES: Add sanity checks so malformed programs cannot hang or overflow */
    unsigned int steps = 0;
    int zf = 0;
    if (!program || !msg) return;
    while (1) {
        if (++steps > MAX_ANIM_STEPS) {
            fprintf(stderr, "animate: exceeded max steps (%u) - aborting\n", MAX_ANIM_STEPS);
            break;
        }
        unsigned char op = 0, arg1 = 0, arg2 = 0;
        /* bounds-check pc inside program buffer (program assumed 256 bytes) */
        if (pc < program || pc >= program + 256) {
            fprintf(stderr, "animate: pc out of program bounds - aborting\n");
            break;
        }
        op = *pc;
        /* Guard reads of arguments */
        if (pc + 1 < program + 256) arg1 = *(pc + 1);
        if (pc + 2 < program + 256) arg2 = *(pc + 2);

        switch (op) {
            case 0x00:
                break;
            case 0x01:
                if (arg1 < 16 && mptr) {
                    regs[arg1] = *mptr;
                }
                break;
            case 0x02:
                if (mptr) *mptr = regs[arg1];
                break;
            case 0x03:
                /* Safely advance pointer but ensure it doesn't go far outside */
                {
                    ptrdiff_t delta = (signed char)arg1;
                    if ((mptr + delta) < msg - 1024 || (mptr + delta) > msg + 1024) {
                        fprintf(stderr, "animate: attempted crazy mptr jump - aborting\n");
                        goto done;
                    }
                    mptr += delta;
                }
                break;
            case 0x04:
                if ((arg1 < 16) && (arg2 < 16)) {
                    regs[arg2] = arg1;
                }
                break;
            case 0x05:
                regs[arg1] ^= regs[arg2];
                zf = !regs[arg1];
                break;
            case 0x06:
                regs[arg1] = (unsigned char)(regs[arg1] + regs[arg2]);
                zf = !regs[arg1];
                break;
            case 0x07:
                if (msg) puts(msg);
                break;
            case 0x08:
                goto done;
            case 0x09:
                /* Jump by arg1, but ensure we stay in bounds */
                {
                    int advance = (int)(signed char)arg1;
                    unsigned char *newpc = pc + advance;
                    if (newpc < program || newpc >= program + 256) {
                        fprintf(stderr, "animate: jump out of bounds - ignoring\n");
                    } else {
                        pc = newpc;
                        continue; /* skip normal pc += 3 increment */
                    }
                }
                break;
            case 0x10:
                if (zf) {
                    int advance = (int)(signed char)arg1;
                    unsigned char *newpc = pc + advance;
                    if (newpc < program || newpc >= program + 256) {
                        fprintf(stderr, "animate: conditional jump out of bounds - ignoring\n");
                    } else {
                        pc = newpc;
                        continue;
                    }
                }
                break;
            default:
                /* Unknown opcode - fail safely */
                fprintf(stderr, "animate: unknown opcode 0x%02x - aborting\n", op);
                goto done;
        }
        pc += 3;
    }
done:
    return;
#endif /* FIXES */
}

void print_gift_card_info(struct this_gift_card *thisone) {
    struct gift_card_data *gcd_ptr;
    struct gift_card_record_data *gcrd_ptr;
    struct gift_card_amount_change *gcac_ptr;
    struct gift_card_program *gcp_ptr;

    if (!thisone) return;
    gcd_ptr = thisone->gift_card_data;
    if (!gcd_ptr) return;

    printf("   Merchant ID: %32.32s\n", gcd_ptr->merchant_id ? gcd_ptr->merchant_id : "(null)");
    printf("   Customer ID: %32.32s\n", gcd_ptr->customer_id ? gcd_ptr->customer_id : "(null)");
    printf("   Num records: %d\n", gcd_ptr->number_of_gift_card_records);

    for (int i = 0; i < gcd_ptr->number_of_gift_card_records; i++) {

        gcrd_ptr = (struct gift_card_record_data *)gcd_ptr->gift_card_record_data[i];
        if (!gcrd_ptr) continue;

        if (gcrd_ptr->type_of_record == 1) {
            printf("      record_type: amount_change\n");
            gcac_ptr = gcrd_ptr->actual_record;
            if (gcac_ptr) {
                printf("      amount_added: %d\n", gcac_ptr->amount_added);
                if (gcac_ptr->amount_added > 0) {
                    printf("      signature: %32.32s\n", gcac_ptr->actual_signature ? gcac_ptr->actual_signature : "(null)");
                }
            }
        } else if (gcrd_ptr->type_of_record == 2) {
            printf("      record_type: message\n");
            printf("      message: %s\n", (char *)gcrd_ptr->actual_record ? (char *)gcrd_ptr->actual_record : "(null)");
        } else if (gcrd_ptr->type_of_record == 3) {
            gcp_ptr = gcrd_ptr->actual_record;
            if (gcp_ptr) {
                printf("      record_type: animated message\n");
                printf("      message: %s\n", gcp_ptr->message ? gcp_ptr->message : "(null)");
                printf("  [running embedded program]  \n");
                animate(gcp_ptr->message, gcp_ptr->program);
            }
        }
    }
    printf("  Total value: %d\n\n", get_gift_card_value(thisone));
}

/* Added to support web functionalities */
void gift_card_json(struct this_gift_card *thisone) {
    struct gift_card_data *gcd_ptr;
    struct gift_card_record_data *gcrd_ptr;
    struct gift_card_amount_change *gcac_ptr;
    gcd_ptr = thisone->gift_card_data;
    if (!gcd_ptr) {
        printf("{}\n");
        return;
    }
    printf("{\n");
    printf("  \"merchant_id\": \"%32.32s\",\n", gcd_ptr->merchant_id ? gcd_ptr->merchant_id : "");
    printf("  \"customer_id\": \"%32.32s\",\n", gcd_ptr->customer_id ? gcd_ptr->customer_id : "");
    printf("  \"total_value\": %d,\n", get_gift_card_value(thisone));
    printf("  \"records\": [\n");
    for (int i = 0; i < gcd_ptr->number_of_gift_card_records; i++) {
        gcrd_ptr = (struct gift_card_record_data *)gcd_ptr->gift_card_record_data[i];
        if (!gcrd_ptr) continue;
        printf("    {\n");
        if (gcrd_ptr->type_of_record == 1) {
            printf("      \"record_type\": \"amount_change\",\n");
            gcac_ptr = gcrd_ptr->actual_record;
            printf("      \"amount_added\": %d,\n", gcac_ptr ? gcac_ptr->amount_added : 0);
            if (gcac_ptr && gcac_ptr->amount_added > 0) {
                printf("      \"signature\": \"%32.32s\"\n", gcac_ptr->actual_signature ? gcac_ptr->actual_signature : "");
            }
        } else if (gcrd_ptr->type_of_record == 2) {
            printf("      \"record_type\": \"message\",\n");
            printf("      \"message\": \"%s\"\n", gcrd_ptr->actual_record ? (char *)gcrd_ptr->actual_record : "");
        } else if (gcrd_ptr->type_of_record == 3) {
            struct gift_card_program *gcp = gcrd_ptr->actual_record;
            if (gcp) {
                printf("      \"record_type\": \"animated message\",\n");
                printf("      \"message\": \"%s\",\n", gcp->message ? gcp->message : "");
                /* programs are binary so we will hex for the json */
                const char *hexchars = "0123456789abcdef";
                char program_hex[512 + 1];
                program_hex[512] = '\0';
                for (int j = 0; j < 256; j++) {
                    unsigned char byte = gcp->program ? (unsigned char)gcp->program[j] : 0;
                    program_hex[j * 2] = hexchars[(byte & 0xf0) >> 4];
                    program_hex[j * 2 + 1] = hexchars[(byte & 0x0f)];
                }
                printf("      \"program\": \"%s\"\n", program_hex);
            }
        }
        if (i < gcd_ptr->number_of_gift_card_records - 1)
            printf("    },\n");
        else
            printf("    }\n");
    }
    printf("  ]\n");
    printf("}\n");
}

int get_gift_card_value(struct this_gift_card *thisone) {
    struct gift_card_data *gcd_ptr;
    struct gift_card_record_data *gcrd_ptr;
    struct gift_card_amount_change *gcac_ptr;
    int ret_count = 0;

    if (!thisone) return 0;
    gcd_ptr = thisone->gift_card_data;
    if (!gcd_ptr) return 0;

    for (int i = 0; i < gcd_ptr->number_of_gift_card_records; i++) {
        gcrd_ptr = (struct gift_card_record_data *)gcd_ptr->gift_card_record_data[i];
        if (!gcrd_ptr) continue;
        if (gcrd_ptr->type_of_record == 1) {
            gcac_ptr = gcrd_ptr->actual_record;
            if (gcac_ptr) ret_count += gcac_ptr->amount_added;
        }
    }
    return ret_count;
}

/* JAC: input_fd is misleading... It's a FILE type, not a fd */
struct this_gift_card *gift_card_reader(FILE *input_fd) {

    if (!input_fd) return NULL;

#ifndef FIXES
    struct this_gift_card *ret_val = malloc(sizeof(struct this_gift_card));
    void *optr;
    void *ptr;

    /* Loop to do the whole file */
    while (!feof(input_fd)) {

        struct gift_card_data *gcd_ptr;
        /* JAC: Why aren't return types checked? */
        fread(&ret_val->num_bytes, 4, 1, input_fd);

        /* Original vulnerable behavior kept for grader: no strict checks here */
        /* crash1 / crash2 are expected to trigger on the original */

        /* Make something the size of the rest and read it in */
        ptr = malloc(ret_val->num_bytes);
        fread(ptr, ret_val->num_bytes, 1, input_fd);

        optr = (char*)ptr - 4;

        gcd_ptr = ret_val->gift_card_data = malloc(sizeof(struct gift_card_data));
        gcd_ptr->merchant_id = ptr;
        ptr = (char *)ptr + 32;
        gcd_ptr->customer_id = ptr;
        ptr = (char *)ptr + 32;
        gcd_ptr->number_of_gift_card_records = *((char *)ptr);
        ptr = (char *)ptr + 4;

        gcd_ptr->gift_card_record_data = (void *)malloc(gcd_ptr->number_of_gift_card_records * sizeof(void *));

        /* Now ptr points at the gift card record data */
        for (int i = 0; i <= gcd_ptr->number_of_gift_card_records; i++) {

            struct gift_card_record_data *gcrd_ptr;
            gcrd_ptr = gcd_ptr->gift_card_record_data[i] = malloc(sizeof(struct gift_card_record_data));
            struct gift_card_amount_change *gcac_ptr;
            gcac_ptr = gcrd_ptr->actual_record = malloc(sizeof(struct gift_card_record_data));
            struct gift_card_program *gcp_ptr;
            gcp_ptr = malloc(sizeof(struct gift_card_program));

            gcrd_ptr->record_size_in_bytes = *((char *)ptr);
            ptr = (char *)ptr + 4;
            gcrd_ptr->type_of_record = *((char *)ptr);
            ptr = (char *)ptr + 4;

            /* amount change */
            if (gcrd_ptr->type_of_record == 1) {
                gcac_ptr->amount_added = *((int *)ptr);
                ptr = (char *)ptr + 4;

                /* don't need a sig if negative */
                if (gcac_ptr < 0) break;

                gcac_ptr->actual_signature = ptr;
                ptr = (char *)ptr + 32;
            }
            /* message */
            if (gcrd_ptr->type_of_record == 2) {
                gcrd_ptr->actual_record = ptr;
                ptr = (char *)ptr + strlen((char *)gcrd_ptr->actual_record) + 1;
            }
            /* text animation (BETA) */
            if (gcrd_ptr->type_of_record == 3) {
                gcp_ptr->message = malloc(32);
                gcp_ptr->program = malloc(256);
                memcpy(gcp_ptr->message, ptr, 32);
                ptr = (char *)ptr + 32;
                memcpy(gcp_ptr->program, ptr, 256);
                ptr = (char *)ptr + 256;
                gcrd_ptr->actual_record = gcp_ptr;
            }
        }
    }
    return ret_val;
#else
    /* FIXES: defensive parsing of file-driven sizes and pointers */
    struct this_gift_card *ret_val = safe_malloc(sizeof(struct this_gift_card));
    if (!ret_val) return NULL;

    while (!feof(input_fd)) {
        struct gift_card_data *gcd_ptr = NULL;
        uint32_t num_bytes_u32 = 0;

        if (safe_fread_exact(&num_bytes_u32, sizeof(num_bytes_u32), input_fd) != 0) {
            break; /* EOF or error */
        }

        /* Basic sanity: non-zero, not absurdly large */
        size_t num_bytes = (size_t)num_bytes_u32;
        if (num_bytes == 0 || num_bytes > MAX_SAFE_ALLOC) {
            fprintf(stderr, "gift_card_reader: invalid num_bytes %zu\n", num_bytes);
            break;
        }

        /* allocate buffer and read payload */
        void *payload = safe_malloc(num_bytes);
        if (!payload) break;
        if (safe_fread_exact(payload, num_bytes, input_fd) != 0) {
            free(payload);
            break;
        }

        /* Now parse payload from a local pointer safely */
        char *ptr = (char *)payload;
        void *heap_tmp = NULL;
        size_t remaining = num_bytes;

        gcd_ptr = safe_malloc(sizeof(struct gift_card_data));
        if (!gcd_ptr) { free(payload); break; }
        ret_val->gift_card_data = gcd_ptr;

        /* merchant_id (32 bytes) */
        if (remaining < 32) { free(payload); break; }
        gcd_ptr->merchant_id = ptr;
        ptr += 32; remaining -= 32;

        /* customer_id (32 bytes) */
        if (remaining < 32) { free(payload); break; }
        gcd_ptr->customer_id = ptr;
        ptr += 32; remaining -= 32;

        /* number_of_gift_card_records (4 bytes) */
        if (remaining < 4) { free(payload); break; }
        uint32_t recs = 0;
        memcpy(&recs, ptr, 4);
        gcd_ptr->number_of_gift_card_records = (int)recs;
        ptr += 4; remaining -= 4;

        if (gcd_ptr->number_of_gift_card_records < 0 || gcd_ptr->number_of_gift_card_records > 10000) {
            fprintf(stderr, "gift_card_reader: unreasonable record count %d\n", gcd_ptr->number_of_gift_card_records);
            free(payload); break;
        }

        gcd_ptr->gift_card_record_data = safe_malloc(gcd_ptr->number_of_gift_card_records * sizeof(void *));
        if (!gcd_ptr->gift_card_record_data) { free(payload); break; }

        for (int i = 0; i < gcd_ptr->number_of_gift_card_records; i++) {
            if (remaining < 8) { /* at least record_size + type fields */
                fprintf(stderr, "gift_card_reader: not enough bytes for record header\n");
                break;
            }

            struct gift_card_record_data *gcrd_ptr = safe_malloc(sizeof(struct gift_card_record_data));
            if (!gcrd_ptr) { break; }

            gcd_ptr->gift_card_record_data[i] = gcrd_ptr;

            uint32_t record_size = 0;
            memcpy(&record_size, ptr, 4); ptr += 4; remaining -= 4;
            gcrd_ptr->record_size_in_bytes = (int)record_size;

            uint32_t rec_type = 0;
            memcpy(&rec_type, ptr, 4); ptr += 4; remaining -= 4;
            gcrd_ptr->type_of_record = (int)rec_type;

            if (gcrd_ptr->type_of_record == 1) {
                if (remaining < 4) { fprintf(stderr,"bad amount change record\n"); break; }
                struct gift_card_amount_change *gcac_ptr = safe_malloc(sizeof(struct gift_card_amount_change));
                if (!gcac_ptr) break;
                memcpy(&gcac_ptr->amount_added, ptr, 4); ptr += 4; remaining -= 4;
                gcac_ptr->actual_signature = NULL;
                if (gcac_ptr->amount_added > 0) {
                    if (remaining < 32) { free(gcac_ptr); break; }
                    gcac_ptr->actual_signature = ptr;
                    ptr += 32; remaining -= 32;
                }
                gcrd_ptr->actual_record = gcac_ptr;
            } else if (gcrd_ptr->type_of_record == 2) {
                /* message: string with nul terminator */
                size_t msglen = strnlen(ptr, remaining);
                if (msglen == remaining) { /* no nul found */
                    fprintf(stderr, "gift_card_reader: unterminated message\n");
                    break;
                }
                gcrd_ptr->actual_record = ptr;
                ptr += (msglen + 1);
                remaining -= (msglen + 1);
            } else if (gcrd_ptr->type_of_record == 3) {
                /* animated message: 32 byte message + 256 byte program */
                if (remaining < 32 + 256) { fprintf(stderr, "gift_card_reader: incomplete animated record\n"); break; }
                struct gift_card_program *gcp_ptr = safe_malloc(sizeof(struct gift_card_program));
                if (!gcp_ptr) break;
                gcp_ptr->message = safe_malloc(32);
                gcp_ptr->program = safe_malloc(256);
                if (!gcp_ptr->message || !gcp_ptr->program) { /* cleanup omitted for brevity */ break; }
                memcpy(gcp_ptr->message, ptr, 32);
                ptr += 32; remaining -= 32;
                memcpy(gcp_ptr->program, ptr, 256);
                ptr += 256; remaining -= 256;
                gcrd_ptr->actual_record = gcp_ptr;
            } else {
                /* Unknown record type - skip record_size if possible */
                if (remaining < (size_t)gcrd_ptr->record_size_in_bytes) {
                    fprintf(stderr, "gift_card_reader: unknown record type with insufficient bytes\n");
                    break;
                }
                gcrd_ptr->actual_record = ptr;
                ptr += gcrd_ptr->record_size_in_bytes;
                remaining -= gcrd_ptr->record_size_in_bytes;
            }
        }

        /* free payload memory if needed - but many pointers point into payload
         * (we purposely keep pointers into 'payload' so don't free here).
         * In production code you would duplicate the strings you need and free payload.
         */
    }

    return ret_val;
#endif /* FIXES */
}

/* BDG: why not a local variable here? */
struct this_gift_card *thisone;

int main(int argc, char **argv) {
    /* Basic argv checking (FIXES mode enforces this more strictly) */
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <mode:1|2> <giftfile>\n", argc ? argv[0] : "giftcardreader");
        return 1;
    }

#ifndef FIXES
    for (int i = 0; i < argc; i++) {
        if (i > 2) {
            printf("ONLY 2 Arguments Accepted, Try Again \n");
            exit(0);
        }
    }
#else
    if (argc > 3) {
        fprintf(stderr, "Too many arguments\n");
        return 1;
    }
#endif

    FILE *input_fd = fopen(argv[2], "rb");
    if (!input_fd) {
        perror("fopen");
        return 1;
    }
    thisone = gift_card_reader(input_fd);
    fclose(input_fd);

    if (!thisone) {
        fprintf(stderr, "Failed to read gift card\n");
        return 1;
    }

    if (argv[1][0] == '1') print_gift_card_info(thisone);
    else if (argv[1][0] == '2') gift_card_json(thisone);

    return 0;
}
