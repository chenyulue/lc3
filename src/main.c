#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#ifdef _WIN32
#include <conio.h>
#include <windows.h>

HANDLE hStdin = INVALID_HANDLE_VALUE;
DWORD fdwMode, fdwOldMode;

void disable_input_buffering() {
    hStdin = GetStdHandle(STD_INPUT_HANDLE);
    GetConsoleMode(hStdin, &fdwOldMode);
    fdwMode = fdwOldMode ^ ENABLE_ECHO_INPUT ^ ENABLE_LINE_INPUT;
    SetConsoleMode(hStdin, fdwMode);
    FlushConsoleInputBuffer(hStdin);
}

void restore_input_buffering() { SetConsoleMode(hStdin, fdwOldMode); }

uint16_t check_key() {
    return WaitForSingleObject(hStdin, 1000) == WAIT_OBJECT_0 && _kbhit();
}

#else
#include <fcntl.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/termios.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

struct termios original_tio;

void disable_input_buffering() {
    tcgetattr(STDIN_FILENO, &original_tio);
    struct termios new_tio = original_tio;
    new_tio.c_lflag &= ~ICANON & ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &new_tio);
}

void restore_input_buffering() {
    tcsetattr(STDIN_FILENO, TCSANOW, &original_tio);
}

uint16_t check_key() {
    fd_set readfds;
    FD_ZERO(&readfds);
    FD_SET(STDIN_FILENO, &readfds);

    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 0;
    return select(1, &readfds, NULL, NULL, &timeout) != 0;
}
#endif

#define MEMORY_MAX (1 << 16)

enum reg {
    R_R0 = 0,
    R_R1,
    R_R2,
    R_R3,
    R_R4,
    R_R5,
    R_R6,
    R_R7,
    R_PC, /* Program counter */
    R_COND,
    R_COUNT
};

typedef enum op_code OpCode;
enum op_code {
    OP_BR = 0, /* branch */
    OP_ADD,    /* add */
    OP_LD,     /* load */
    OP_ST,     /* store */
    OP_JSR,    /* jump register*/
    OP_AND,    /* bitwise and */
    OP_LDR,    /* load register */
    OP_STR,    /* store register */
    OP_RTI,    /* unused */
    OP_NOT,    /* bitwise not */
    OP_LDI,    /* load indirect */
    OP_STI,    /* store indirect */
    OP_JMP,    /* jump */
    OP_RES,    /* reserved (unused)*/
    OP_LEA,    /* load effective address */
    OP_TRAP    /* execute trap */
};

typedef enum vm_state VMState;
enum vm_state {
    VM_SUCCESS,
    ERROR_UNKNOWN_OPCODE,
};

enum cond_flag {
    FL_POS = 1 << 0,
    FL_ZRO = 1 << 1,
    FL_NEG = 1 << 2,
};

enum trap_code {
    TRAP_GETC =
        0x20, /* Get character from keyboard, not echoed onto the terminal */
    TRAP_OUT = 0x21,  /* Output a character */
    TRAP_PUTS = 0x22, /* Output a word string */
    TRAP_IN = 0x23, /* Get character from keyboard, echoed onto the terminal */
    TRAP_PUTSP = 0x24, /* Output a byte string */
    TRAP_HALT = 0x25,  /* Halt the program*/
};

enum mem_m_reg {
    MR_KBSR = 0xFF00, /* Keyboard status */
    MR_KBDR = 0xFF02  /* Keyboard data */
};

typedef struct {
    VMState state;
    bool running;
    uint16_t PC_START;
    uint16_t memory[MEMORY_MAX]; /* 2^16 locations */
    uint16_t reg[R_COUNT];
} VM;

void memWrite(VM *vm, uint16_t addr, uint16_t val) { vm->memory[addr] = val; }

uint16_t memRead(VM *vm, uint16_t addr) {
    if (addr == MR_KBSR) {
        if (check_key()) {
            vm->memory[MR_KBSR] = (1 << 15);
            vm->memory[MR_KBDR] = getchar();
        } else {
            vm->memory[MR_KBSR] = 0;
        }
    }
    return vm->memory[addr];
}

void vmReset(VM *vm) {
    *vm = (VM){0};
    vm->PC_START = 0x3000;
    vm->reg[R_PC] = vm->PC_START;
    vm->running = true;
}

uint16_t signExtend(uint16_t x, int bitCount) {
    return (x >> (bitCount - 1) & 1) ? (x | 0xFFFF << bitCount) : x;
}

void updateFlags(VM *vm, uint16_t r) {
    if (vm->reg[r] == 0)
        vm->reg[R_COND] = FL_ZRO;
    else if (vm->reg[r] >> 15)
        vm->reg[R_COND] = FL_NEG;
    else
        vm->reg[R_COND] = FL_POS;
}

#define OP(i) ((i) >> 12)
#define DR(i) ((i) >> 9 & 0x7)
#define SR1(i) ((i) >> 6 & 0x7)
#define SR2(i) ((i)&0x7)
#define IMM(i, n) ((i) & (n))
#define IMM5(i) signExtend(IMM(i, 0x1F), 5)
#define BIT_F(i, n) ((i) >> n & 0x1)
#define SETCC(r) updateFlags(vm, r)
#define PC_OFFSET9(i) signExtend(IMM(i, 0x1FF), 9)
#define PC_OFFSET11(i) signExtend(IMM(i, 0x7FF), 11)
#define BS_OFFSET6(i) signExtend(IMM(i, 0x3F), 6)
#define COND_F(i) DR(i)
#define BASE_R(i) SR1(i)
#define TRAP_VECT8(i) ((i)&0xFF)

void trap(VM *vm, uint16_t instr) {
    switch (TRAP_VECT8(instr)) {
        case TRAP_GETC: {
            vm->reg[R_R0] = (uint16_t)getchar();
            SETCC(R_R0);
            break;
        }
        case TRAP_OUT: {
            putc((char)vm->reg[R_R0], stdout);
            fflush(stdout);
            break;
        }
        case TRAP_PUTS: {
            uint16_t *c = vm->memory + vm->reg[R_R0];
            while (*c) {
                putc((char)*c, stdout);
                c++;
            }
            fflush(stdout);
            break;
        }
        case TRAP_IN: {
            printf("Enter a character: ");
            char c = getchar();
            putc(c, stdout);
            fflush(stdout);
            vm->reg[R_R0] = (uint16_t)c;
            SETCC(R_R0);
            break;
        }
        case TRAP_PUTSP: {
            uint16_t *c = vm->memory + vm->reg[R_R0];
            while (*c) {
                char chr1 = (*c) & 0xff;
                putc(chr1, stdout);
                char chr2 = (*c) >> 8;
                if (chr2) putc(chr2, stdout);
                c++;
            }
            fflush(stdout);
            break;
        }
        case TRAP_HALT: {
            puts("HALT");
            fflush(stdout);
            vm->running = false;
            break;
        }
        default: {
            vm->state = ERROR_UNKNOWN_OPCODE;
            break;
        }
    }
}

void run(VM *vm, uint16_t instr) {
    switch (OP(instr)) {
        case OP_ADD: {
            vm->reg[DR(instr)] =
                vm->reg[SR1(instr)] +
                (BIT_F(instr, 5) ? IMM5(instr) : vm->reg[SR2(instr)]);
            SETCC(DR(instr));
            break;
        }
        case OP_AND: {
            vm->reg[DR(instr)] =
                vm->reg[SR1(instr)] &
                (BIT_F(instr, 5) ? IMM5(instr) : vm->reg[SR2(instr)]);
            SETCC(DR(instr));
            break;
        }
        case OP_NOT: {
            vm->reg[DR(instr)] = ~(vm->reg[SR1(instr)]);
            SETCC(DR(instr));
            break;
        }
        case OP_BR: {
            if (COND_F(instr) & vm->reg[R_COND])
                vm->reg[R_PC] += PC_OFFSET9(instr);
            break;
        }
        case OP_JMP: {
            vm->reg[R_PC] = vm->reg[BASE_R(instr)];
            break;
        }
        case OP_JSR: {
            vm->reg[R_R7] = vm->reg[R_PC];
            if (BIT_F(instr, 11)) {
                vm->reg[R_PC] += PC_OFFSET11(instr);
            } else {
                vm->reg[R_PC] = vm->reg[BASE_R(instr)];
            }
            break;
        }
        case OP_LD: {
            vm->reg[DR(instr)] =
                memRead(&vm, vm->reg[R_PC] + PC_OFFSET9(instr));
            SETCC(DR(instr));
            break;
        }
        case OP_LDI: {
            vm->reg[DR(instr)] =
                memRead(&vm, memRead(&vm, vm->reg[R_PC] + PC_OFFSET9(instr)));
            SETCC(DR(instr));
            break;
        }
        case OP_LDR: {
            vm->reg[DR(instr)] =
                memRead(&vm, vm->reg[BASE_R(instr)] + BS_OFFSET6(instr));
            SETCC(DR(instr));
            break;
        }
        case OP_LEA: {
            vm->reg[DR(instr)] = vm->reg[R_PC] + PC_OFFSET9(instr);
            SETCC(DR(instr));
            break;
        }
        case OP_ST: {
            memWrite(&vm, vm->reg[R_PC] + PC_OFFSET9(instr),
                     vm->reg[DR(instr)]);
            break;
        }
        case OP_STI: {
            memWrite(&vm, memRead(&vm, vm->reg[R_PC] + PC_OFFSET9(instr)),
                     vm->reg[DR(instr)]);
            break;
        }
        case OP_STR: {
            memWrite(&vm, vm->reg[BASE_R(instr)] + BS_OFFSET6(instr),
                     vm->reg[DR(instr)]);
            break;
        }
        case OP_TRAP: {
            vm->reg[R_R7] = vm->reg[R_PC];
            trap(vm, instr);
            break;
        }
        case OP_RES:
        case OP_RTI:
        default: {
            abort();
            break;
        }
    }
}

#undef OP
#undef DR
#undef SR1
#undef SR2
#undef IMM
#undef IMM5
#undef BIT_F
#undef SETCC
#undef PC_OFFSET9
#undef PC_OFFSET11
#undef BS_OFFSET6
#undef COND_F
#undef BASE_R
#undef TRAP_VECT8

static inline uint16_t swap16(uint16_t x) { return (x << 8) | (x >> 8); }

void readImageFile(VM *vm, FILE *file) {
    uint16_t origin;
    fread(&origin, sizeof(origin), 1, file);
    origin = swap16(origin);

    uint16_t max_read = MEMORY_MAX - origin;
    uint16_t *p = vm->memory + origin;
    size_t read = fread(p, sizeof(uint16_t), max_read, file);

    while (read-- > 0) {
        *p = swap16(*p);
        p++;
    }
}

int readImage(VM *vm, const char *imagePath) {
    FILE *file = fopen(imagePath, "rb");
    if (!file) {
        return 0;
    }
    readImageFile(vm, file);
    fclose(file);
    return 1;
}

void handle_interrupt(int signal) {
    restore_input_buffering();
    printf("\n");
    exit(-2);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("lc3 [image-file1] ...\n");
        exit(2);
    }

    VM vm;
    vmReset(&vm);

    for (int i = 1; i < argc; i++) {
        if (!readImage(&vm, argv[i])) {
            fprintf(stderr, "failed to load image: %s\n", argv[i]);
            exit(1);
        }
    }

    signal(SIGINT, handle_interrupt);
    disable_input_buffering();

    while (vm.running) {
        uint16_t instr = memRead(&vm, vm.reg[R_PC]);
        vm.reg[R_PC]++;
        run(&vm, instr);
    }

    restore_input_buffering();
    return 0;
}
