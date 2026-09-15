#include <fcntl.h>				// open
#include <iostream>				// cin
#include <sstream>				// ifstream
#include <assert.h>				// asert
#include <stdio.h>				// fprintf
#include <stdlib.h>				// stoi stol
#include <sys/wait.h>			// waitpid
#include <sys/ptrace.h>			// ptrace
#include <sys/user.h>			// struct user_regs_struct
#include <cstring>				// memcpy strcpy strrchr
#include <vector>				// c++ vector
#include <algorithm>            // c++ vector find
#include <capstone/capstone.h>	// disassemble
#include <limits.h>             // PATH_MAX
#include <elf.h>                // AT_ENTRY
#include "ptools.h"				// map<range_t, map_entry_t> vmmap
using namespace std;

void errquit(const char *msg) {
	perror(msg);
	exit(-1);
}

struct breakInfo {
    vector<int> num;
    unsigned char originalByte;
    bool active;
    bool hit;
};

constexpr unsigned char INT3 = 0xcc;
map<unsigned long, struct breakInfo> breakInfoMap;
int max_break_index = -2;
int mem_fd;
int status;

// Capstone Variable
csh handle;
cs_insn *insn;

unsigned char poke_byte(pid_t child, unsigned long addr, unsigned char byte) {
    unsigned long offset = addr % 8;
    unsigned long word_addr = addr - offset;
    errno = 0;
    long word = ptrace(PTRACE_PEEKTEXT, child, (void*)word_addr, 0);
    if (word == -1 && errno != 0)
        return (unsigned char)0;
    unsigned long long mask = 0xffULL << (offset * 8);
    long patch = (word & ~mask) | ((unsigned long long)byte << (offset * 8));
    if (ptrace(PTRACE_POKETEXT, child, (void*)word_addr, (void*)patch) != 0)
        errquit("ptrace(PTRACE_POKETEXT)");
    return (word >> (offset * 8)) & 0xff;
}

int recovery_oneStep_restore(int child) {
	// find break point
	unsigned long addr = 0x0;
    for (auto breakPoints: breakInfoMap)
        if (breakPoints.second.hit)
            addr = breakPoints.first;
    if (!addr) {
        return 1;
    }

	// recovery
	poke_byte(child, addr, breakInfoMap[addr].originalByte);
	
	// oneStep
	if (ptrace(PTRACE_SINGLESTEP, child, 0, 0) != 0)
		errquit("ptrace(PTRACE_SINGLESTEP)");

	// restore break points
	if (waitpid(child, &status, 0) > 0 && WIFSTOPPED(status))
		if (breakInfoMap[addr].active)
			poke_byte(child, addr, INT3);
	breakInfoMap[addr].hit = false;

    if (WIFEXITED(status)) {
        fprintf(stderr, "** the target program terminated.\n");
        close(mem_fd);
        cs_close(&handle);
        exit(0);
    }

	return 0;
}

void disassemble(unsigned long start, pid_t child_pid, size_t showLine) {
	size_t size = showLine * 16;
	uint8_t *buffer = new uint8_t[size];

	// Try to read memory from child process
	ssize_t bytes_read = pread(mem_fd, buffer, size, start);
	if (bytes_read <= 0) {
		close(mem_fd);
		delete[] buffer;
		errquit("pread from /proc/[pid]/mem");
	}

	for (size_t i = 0; i < size; ++i)
		for (auto breakPoint: breakInfoMap)
			if (breakPoint.first == start + i)
				buffer[i] = breakPoint.second.originalByte;

    map<range_t, map_entry_t> cur;
    load_maps(child_pid, cur);
    unsigned long end = 0;
    for (auto& e : cur) {
        if ((e.second.perm & 0x01) && e.second.range.begin <= start && start < e.second.range.end) {
            end = e.second.range.end;
            break;
        }
    }
    if (end == 0) {
        fprintf(stderr, "** the address is out of the range of the executable region.\n");
        return;
    }

    size = min((size_t)(end - start), size);
    
	// Capstone disassembly
	size_t count = cs_disasm(handle, buffer, size, start, 0, &insn);
	if (count > 0) {
		for (size_t j = 0; j < showLine && j < count; j++) {
			fprintf(stderr, "\t0x%lx: ", insn[j].address);
			for (size_t k = 0; k < insn[j].size; ++k)
				fprintf(stderr, "%02x ", insn[j].bytes[k]);
			for (int p = 0; p < 32 - (insn[j].size * 3); ++p)
				fprintf(stderr, " ");
			fprintf(stderr, "%s\t%s\n", insn[j].mnemonic, insn[j].op_str);
		}
		if (count < showLine)
			fprintf(stderr, "** the address is out of the range of the executable region.\n");
		cs_free(insn, count);
	} else {
		fprintf(stderr, "Failed to disassemble memory at 0x%lx\n", start);
	}
	
	delete[] buffer;
}

bool getSDBCommand(vector<string>& command_list) {
	fprintf(stderr, "(sdb) ");

	string command, token;
    if (!getline(cin, command)) {
        return false;
    }
    if (command.find_first_not_of(" \t\r\n") == string::npos) {
        return true;
    }
    command_list.clear();

	istringstream iss(command);
    while (iss >> token)
		command_list.push_back(token);
    
    return true;
}

unsigned long get_auxv_entry(pid_t pid) {
	char path[64];
	snprintf(path, sizeof(path), "/proc/%d/auxv", pid);
	FILE* f = fopen(path, "rb");
	if (!f)
		return 0;

	unsigned long key, val;
	while (fread(&key, sizeof(key), 1, f) == 1 && fread(&val, sizeof(val), 1, f) == 1) {
		if (key == AT_ENTRY) {
			fclose(f);
			return val;
		}
	}
	fclose(f);
	return 0;
}

int exeSDBcommand(pid_t child, vector<string>& command_list, unsigned long baseaddr) {
    struct user_regs_struct regs;
    unsigned long addr;

	if (command_list[0] == "info" && command_list[1] == "reg") {
		if (ptrace(PTRACE_GETREGS, child, 0, &regs) != 0)
			errquit("ptrace(GETREGS)");
		fprintf(stderr, "$rax 0x%016llx\t$rbx 0x%016llx\t$rcx 0x%016llx\n", regs.rax, regs.rbx, regs.rcx);
		fprintf(stderr, "$rdx 0x%016llx\t$rsi 0x%016llx\t$rdi 0x%016llx\n", regs.rdx, regs.rsi, regs.rdi);
		fprintf(stderr, "$rbp 0x%016llx\t$rsp 0x%016llx\t$r8  0x%016llx\n", regs.rbp, regs.rsp, regs.r8);
		fprintf(stderr, "$r9  0x%016llx\t$r10 0x%016llx\t$r11 0x%016llx\n", regs.r9, regs.r10, regs.r11);
		fprintf(stderr, "$r12 0x%016llx\t$r13 0x%016llx\t$r14 0x%016llx\n", regs.r12, regs.r13, regs.r14);
		fprintf(stderr, "$r15 0x%016llx\t$rip 0x%016llx\t$eflags 0x%016llx\n", regs.r15, regs.rip, regs.eflags);
	} else if (command_list[0] == "info" && command_list[1] == "break") {
		bool exist_breakPoint = false;
		for (auto breakPoint: breakInfoMap) {
			if (breakPoint.second.active) {
				exist_breakPoint = true;
				break;
			}
		}
		if (exist_breakPoint) {
			fprintf(stderr, "Num\tAddress\n");
            for (int i = 0; i <= max_break_index; ++i) {
                for (auto breakPoint: breakInfoMap) {
                    if (breakPoint.second.active && find(breakPoint.second.num.begin(), breakPoint.second.num.end(), i) != breakPoint.second.num.end()) {
                        fprintf(stderr, "%d\t0x%lx\n", i, breakPoint.first);
                    }
                }
            }
		} else {
			fprintf(stderr, "** no breakpoints.\n");
		}
	} else if (command_list[0] == "break" || command_list[0] == "breakrva") {
        if (command_list.size() == 1) {
            fprintf(stderr, "** the target address is not valid.\n");
            return 0;
        }

		if (command_list[1].substr(0, 2) != "0x")
			command_list[1] = "0x" + command_list[1];
        try {
            addr = stol(command_list[1], 0, 16) + (command_list[0] == "break" ? 0: baseaddr);
        } catch (const logic_error& e) {
            fprintf(stderr, "** the target address is not valid.\n");
            return 0;
        };
		if (ptrace(PTRACE_GETREGS, child, 0, &regs) != 0)
			errquit("ptrace(GETREGS)");
        if (breakInfoMap.find(addr) != breakInfoMap.end()) {
            breakInfoMap[addr].num.push_back(++max_break_index);
            breakInfoMap[addr].active = true;
            breakInfoMap[addr].hit = addr == regs.rip;
            fprintf(stderr, "** set a breakpoint at 0x%lx.\n", addr);
        } else {
            breakInfoMap[addr] = (struct breakInfo){{++max_break_index}, poke_byte(child, addr, INT3), true, addr == regs.rip};
            if (breakInfoMap[addr].originalByte == (unsigned char)0 && errno != 0) {
                breakInfoMap.erase(addr);
                max_break_index--;
                fprintf(stderr, "** the target address is not valid.\n");
            } else {
                fprintf(stderr, "** set a breakpoint at 0x%lx.\n", addr);
            }
        }

	} else if (command_list[0] == "delete") {
        if (command_list.size() == 1) {
            fprintf(stderr, "** breakpoint does not exist.\n");
            return 0;
        }

		int d_index;
        try {
            d_index = stoi(command_list[1]);
        } catch (const logic_error& e) {
            fprintf(stderr, "** breakpoint %s does not exist.\n", command_list[1].c_str());
            return 0;
        };
        
        addr = 0;
        for (auto breakPoints: breakInfoMap)
            if (find(breakPoints.second.num.begin(), breakPoints.second.num.end(), d_index) != breakPoints.second.num.end())
                addr = breakPoints.first;
        
        if (addr) {
            if (breakInfoMap[addr].num.size() == 1) {
                poke_byte(child, addr, breakInfoMap[addr].originalByte);
                breakInfoMap.erase(addr);
            } else {
                auto it = find(breakInfoMap[addr].num.begin(), breakInfoMap[addr].num.end(), d_index);
                breakInfoMap[addr].num.erase(it);
            }
            fprintf(stderr, "** delete breakpoint %d.\n", d_index);
        } else {
            fprintf(stderr, "** breakpoint %d does not exist.\n", d_index);
        }
	} else if (command_list[0] == "patch") {
        if (command_list.size() == 1 || command_list.size() == 2) {
            fprintf(stderr, "** the target address is not valid.\n");
            return 0;
        }
		if (command_list[1].substr(0, 2) != "0x")
			command_list[1] = "0x" + command_list[1];

        try {
            addr = stol(command_list[1], 0, 16);
        } catch (const logic_error& e) {
            fprintf(stderr, "** the target address is not valid.\n");
            return 0;
        };
		string hex_str = command_list[2];
		vector<uint8_t> bytes;
		for (size_t i = 0; i < hex_str.length(); i += 2) {
			uint8_t byte = (uint8_t) strtol(hex_str.substr(i, 2).c_str(), nullptr, 16);
			bytes.push_back(byte);
		}
		
		vector<unsigned char> original_list;
		for (size_t i = 0; i < bytes.size(); ++i) {
			unsigned char ori = poke_byte(child, addr + i, (unsigned char)bytes[i]);
			original_list.push_back(ori);
			if (ori == (unsigned char)0 && errno != 0) {
				fprintf(stderr, "** the target address is not valid.\n");
				for (size_t j = 0; j < original_list.size(); ++j)
					poke_byte(child, addr + j, original_list[j]);
				return 0;
			}
		}
		fprintf(stderr, "** patch memory at 0x%lx.\n", addr);

        for (auto &breakPoint: breakInfoMap)
			if (breakPoint.second.active && (addr <= breakPoint.first && breakPoint.first < addr + (long)bytes.size()))
				breakPoint.second.originalByte = poke_byte(child, breakPoint.first, INT3);
	} else if (command_list[0] == "si") {
		if (!recovery_oneStep_restore(child))
			return 2;
		if (ptrace(PTRACE_SINGLESTEP, child, 0, 0) != 0)
			errquit("ptrace(PTRACE_SINGLESTEP)");
		return 1;
	} else if (command_list[0] == "cont") {
		recovery_oneStep_restore(child);
		if (ptrace(PTRACE_CONT, child, 0, 0) != 0)
			errquit("ptrace(PTRACE_CONT)");
		return 1;
	} else if (command_list[0] == "syscall") {
		recovery_oneStep_restore(child);
		if (ptrace(PTRACE_SYSCALL, child, 0, 0) != 0)
			errquit("ptrace(PTRACE_SYSCALL)@parent");
		if (waitpid(child, &status, 0) < 0)
			errquit("waitpid");
		if ((!WIFSTOPPED(status) || !(WSTOPSIG(status) & 0x80)) && !WIFEXITED(status))
			return 2;
		if (WIFEXITED(status)) {
			fprintf(stderr, "** the target program terminated.\n");
            close(mem_fd);
            cs_close(&handle);
			exit(0);
		}
		if (ptrace(PTRACE_GETREGS, child, 0, &regs) != 0)
			errquit("ptrace(PTRACE_GETREGS)@parent");
        struct __ptrace_syscall_info si;
        ptrace(PTRACE_GET_SYSCALL_INFO, child, sizeof(si), &si);
        if (si.op == PTRACE_SYSCALL_INFO_ENTRY)
            fprintf(stderr, "** enter a syscall(%lld) at 0x%llx.\n", regs.orig_rax, regs.rip-2);
        else if (si.op == PTRACE_SYSCALL_INFO_EXIT)
            fprintf(stderr, "** leave a syscall(%lld) = %lld at 0x%llx.\n", regs.orig_rax, regs.rax, regs.rip-2);
		disassemble(regs.rip-2, child, 5);
	}
	return 0;
}

int main(int argc, char *argv[]) {
	char exeFilepath[256];
	vector<string> command_list;
    bool inputAlive;
	if(argc > 1) {
		strcpy(exeFilepath, argv[1]);
		command_list.push_back("");
	} else {
        inputAlive = getSDBCommand(command_list);
		while (inputAlive && (command_list.size() != 2 || command_list[0] != "load")) {
			fprintf(stderr, "** please load a program first.\n");
            inputAlive = getSDBCommand(command_list);
		}
        if (!inputAlive)
            return 0;
		strcpy(exeFilepath, command_list[1].c_str());
	}

	pid_t child;
	if ((child = fork()) < 0)
		errquit("fork");
	
	if (child == 0) {
		if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0)
			errquit("ptrace");
		execlp(exeFilepath, exeFilepath, NULL);
		errquit("execvp");
	}

    unsigned long baseaddr, target;
    map<range_t, map_entry_t> vmmap;
    map<range_t, map_entry_t>::iterator vi;

    if (waitpid(child, &status, 0) < 0)
        errquit("waitpid");

    assert(WIFSTOPPED(status));
    ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);

    if(load_maps(child, vmmap) <= 0) {
        fprintf(stderr, "## cannot load memory mappings.\n");
        return -1;
    }

    char realExePath[PATH_MAX];
    char procExeLink[64];
    snprintf(procExeLink, sizeof(procExeLink), "/proc/%d/exe", child);
    ssize_t n = readlink(procExeLink, realExePath, sizeof(realExePath) - 1);
    if (n < 0)
        errquit("readlink /proc/[pid]/exe");
    realExePath[n] = '\0';

    char* exeFilename = strrchr(realExePath, '/');
    exeFilename = exeFilename ? exeFilename + 1 : realExePath;

    for (vi = vmmap.begin(); vi != vmmap.end(); vi++) {
        if (vi->second.name == string(exeFilename)) {
            baseaddr = vi->second.range.begin;
            break;
        }
    }

    // get memory content
    char mem_path[256];
	snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", child);

	mem_fd = open(mem_path, O_RDONLY);
	if (mem_fd == -1)
		errquit("open /proc/[pid]/mem");

    // Capstone init
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
		fprintf(stderr, "cs_open failed\n");
		exit(EXIT_FAILURE);
	}

	cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
	cs_option(handle, CS_OPT_DETAIL, CS_OPT_OFF);

    target = get_auxv_entry(child);
    fprintf(stderr, "** program \'%s\' loaded. entry point: 0x%lx.\n",exeFilepath, target);

    breakInfoMap[target] = (struct breakInfo){{++max_break_index}, poke_byte(child, target, INT3), false};
    ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL|PTRACE_O_TRACESYSGOOD);
    ptrace(PTRACE_CONT, child, 0, 0);
    
    while (waitpid(child, &status, 0) > 0) {
        if (WIFEXITED(status))
            break;
        if (!WIFSTOPPED(status))
            continue;

        int exeReturn = 0;
        while (exeReturn != 1) {
            struct user_regs_struct regs;
            if (ptrace(PTRACE_GETREGS, child, 0, &regs) != 0)
                errquit("ptrace(GETREGS)");

            unsigned long curraddr = 0x0;
            if (command_list[0] != "si" && breakInfoMap.find(regs.rip-1) != breakInfoMap.end())
                curraddr = regs.rip-1;
            else if (breakInfoMap.find(regs.rip) != breakInfoMap.end())
                curraddr = regs.rip;

            if (curraddr) {
                if (breakInfoMap[curraddr].hit)
                    errquit("breakpoint re-entry");
                breakInfoMap[curraddr].hit = true;
                if (breakInfoMap[curraddr].active)
                    fprintf(stderr, "** hit a breakpoint at 0x%lx.\n", curraddr);
                regs.rip = curraddr;
                if (ptrace(PTRACE_SETREGS, child, 0, &regs) != 0)
                    errquit("ptrace(SETREGS)");
            }

            disassemble(regs.rip, child, 5);
            inputAlive = getSDBCommand(command_list);
            while (inputAlive && (exeReturn = exeSDBcommand(child, command_list, baseaddr)) == 0)
                inputAlive = getSDBCommand(command_list);
            if (!inputAlive)
                return 0;
        }
    }
    fprintf(stderr, "** the target program terminated.\n");
    close(mem_fd);
    cs_close(&handle);
	return 0;
}
