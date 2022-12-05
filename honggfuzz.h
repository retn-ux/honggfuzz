/*
 *
 * honggfuzz - core structures and macros
 * -----------------------------------------
 *
 * Author: Robert Swiecki <swiecki@google.com>
 *
 * Copyright 2010-2018 by Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License.
 *
 */

#ifndef _HF_HONGGFUZZ_H_
#define _HF_HONGGFUZZ_H_

#include <dirent.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <time.h>

#include "libhfcommon/util.h"

#define PROG_NAME    "honggfuzz"
#define PROG_VERSION "2.5"

/* Name of the template which will be replaced with the proper name of the file */
#define _HF_FILE_PLACEHOLDER "___FILE___"

/* Default name of the report created with some architectures */
#define _HF_REPORT_FILE "HONGGFUZZ.REPORT.TXT"

/* Default stack-size of created threads. */
#define _HF_PTHREAD_STACKSIZE (1024ULL * 1024ULL * 2ULL) /* 2MB */

/* Name of envvar which indicates sequential number of fuzzer */
#define _HF_THREAD_NO_ENV "HFUZZ_THREAD_NO"

/* Name of envvar which indicates that the netDriver should be used */
#define _HF_THREAD_NETDRIVER_ENV "HFUZZ_USE_NETDRIVER"

/* Name of envvar which indicates honggfuzz's log level in use */
#define _HF_LOG_LEVEL_ENV "HFUZZ_LOG_LEVEL"

/* Number of crash verifier iterations before tag crash as stable */
#define _HF_VERIFIER_ITER 5

/* Size (in bytes) for report data to be stored in stack before written to file */
#define _HF_REPORT_SIZE 32768

/* Perf bitmap size */
#define _HF_PERF_BITMAP_SIZE_16M   (1024U * 1024U * 16U)
#define _HF_PERF_BITMAP_BITSZ_MASK 0x7FFFFFFULL
/* Maximum number of PC guards (=trace-pc-guard) we support */
#define _HF_PC_GUARD_MAX (1024ULL * 1024ULL * 64ULL)

/* Maximum size of the input file in bytes (1 MiB) */
#define _HF_INPUT_MAX_SIZE (1024ULL * 1024ULL)

/* Default maximum size of produced inputs */
#define _HF_INPUT_DEFAULT_SIZE (1024ULL * 8)

/* Per-thread bitmap */
#define _HF_PERTHREAD_BITMAP_FD 1018
/* FD used to report back used int/str constants from the fuzzed process */
#define _HF_CMP_BITMAP_FD 1019
/* FD used to log inside the child process */
#define _HF_LOG_FD 1020
/* FD used to represent the input file */
#define _HF_INPUT_FD 1021
/* FD used to pass coverage feedback from the fuzzed process */
#define _HF_COV_BITMAP_FD 1022
#define _HF_BITMAP_FD     _HF_COV_BITMAP_FD /* Old name for _HF_COV_BITMAP_FD */
/* FD used to pass data to a persistent process */
#define _HF_PERSISTENT_FD 1023

/* Input file as a string */
#define _HF_INPUT_FILE_PATH "/dev/fd/" HF_XSTR(_HF_INPUT_FD)

/* Maximum number of supported execve() args */
#define _HF_ARGS_MAX 2048

/* Message indicating that the fuzzed process is ready for new data */
static const uint8_t HFReadyTag = 'R';

/* Maximum number of active fuzzing threads */
#define _HF_THREAD_MAX 1024U

/* Persistent-binary signature - if found within file, it means it's a persistent mode binary
	Persistent二进制签名——如果在文件中找到，就意味着它是一个Persistent模式二进制（启用Persistent模式）
*/
#define _HF_PERSISTENT_SIG "\x01_LIBHFUZZ_PERSISTENT_BINARY_SIGNATURE_\x02\xFF"
/* HF NetDriver signature - if found within file, it means it's a NetDriver-based binary 
	HF NetDriver签名-如果在文件中找到，这意味着它是一个基于NetDriver的二进制文件

*/
#define _HF_NETDRIVER_SIG "\x01_LIBHFUZZ_NETDRIVER_BINARY_SIGNATURE_\x02\xFF"

/* printf() nonmonetary separator. According to MacOSX's man it's supported there as well */
#define _HF_NONMON_SEP "'"

typedef enum {
    _HF_DYNFILE_NONE         = 0x0,		//静态模式，禁用任何仪器(hw/sw)反馈
    _HF_DYNFILE_INSTR_COUNT  = 0x1,		//使用perf子系统进行指令计数
    _HF_DYNFILE_BRANCH_COUNT = 0x2,		//使用perf子系统进行分支计数
    _HF_DYNFILE_BTS_EDGE     = 0x10,	//使用intel BTS作为唯一边界计数器
    _HF_DYNFILE_IPT_BLOCK    = 0x20,	//使用intel IPT跟踪计数基本块(需要libipt.so)
    _HF_DYNFILE_SOFT         = 0x40,	//通过软件插桩作为反馈驱动
} dynFileMethod_t;

typedef struct {
    uint64_t cpuInstrCnt;
    uint64_t cpuBranchCnt;
    uint64_t bbCnt;
    uint64_t newBBCnt;
    uint64_t softCntPc;
    uint64_t softCntEdge;
    uint64_t softCntCmp;
} hwcnt_t;

typedef enum {
    _HF_STATE_UNSET = 0,
    _HF_STATE_STATIC,
    _HF_STATE_DYNAMIC_DRY_RUN,
    _HF_STATE_DYNAMIC_MAIN,
    _HF_STATE_DYNAMIC_MINIMIZE,
} fuzzState_t;

typedef enum {
    HF_MAYBE = -1,
    HF_NO    = 0,
    HF_YES   = 1,
} tristate_t;

struct _dynfile_t {
    size_t             size;
    uint64_t           cov[4];
    size_t             idx;
    int                fd;
    uint64_t           timeExecUSecs;
    char               path[PATH_MAX];
    struct _dynfile_t* src;
    uint32_t           refs;
    uint8_t*           data;
    TAILQ_ENTRY(_dynfile_t) pointers;
};

typedef struct _dynfile_t dynfile_t;

struct strings_t {
    size_t len;
    TAILQ_ENTRY(strings_t) pointers;
    char s[];
};

typedef struct {
    uint8_t  pcGuardMap[_HF_PC_GUARD_MAX];
    uint8_t  bbMapPc[_HF_PERF_BITMAP_SIZE_16M];
    uint32_t bbMapCmp[_HF_PERF_BITMAP_SIZE_16M];
    uint64_t pidNewPC[_HF_THREAD_MAX];
    uint64_t pidNewEdge[_HF_THREAD_MAX];
    uint64_t pidNewCmp[_HF_THREAD_MAX];
    uint64_t guardNb;
    uint64_t pidTotalPC[_HF_THREAD_MAX];
    uint64_t pidTotalEdge[_HF_THREAD_MAX];
    uint64_t pidTotalCmp[_HF_THREAD_MAX];
} feedback_t;

typedef struct {
    uint32_t cnt;
    struct {
        uint8_t  val[32];
        uint32_t len;
    } valArr[1024 * 16];
} cmpfeedback_t;

typedef struct {
    struct {
        size_t    threadsMax;					//并发模糊测试线程数（默认值：CPU 数 / 2）
        size_t    threadsFinished;
        uint32_t  threadsActiveCnt;
        pthread_t mainThread;
        pid_t     mainPid;
        uint32_t  pinThreadToCPUs;				//将单个执行线程分配到多个连续的 CPU（默认值：0 = 没有 CPU 分配）
        pthread_t threads[_HF_THREAD_MAX];
    } threads;
    struct {
        const char* inputDir;					//输入目录路径
        const char* outputDir;					//输出目录路径
        DIR*        inputDirPtr;				//输入目录对象
        size_t      fileCnt;					//测试文件的个数
        size_t      testedFileCnt;
        const char* fileExtn;					//设置文件扩展名
        size_t      maxFileSz;					//模糊器处理的最大文件大小（以字节为单位）（默认值：1048576 = 1MB）
        size_t      newUnitsAdded;
        char        workDir[PATH_MAX];			//工作区目录（默认值：'.'）
        const char* crashDir;					//崩溃记录保存路径
        const char* covDirNew;				//新的coverage（在dry-run阶段之后）被写入这个单独的目录
        bool        saveUnique;				//是否在文件名上添加时间戳
        bool        saveSmaller;			//是否保存较小的测试用例
        size_t      dynfileqMaxSz;
        size_t      dynfileqCnt;
        dynfile_t*  dynfileqCurrent;
        dynfile_t*  dynfileq2Current;
        TAILQ_HEAD(dyns_t, _dynfile_t) dynfileq;
        bool exportFeedback;				//是否将覆盖率反馈结构导出为./hfuzzy-feedback
    } io;
    struct {
        int                argc;
        const char* const* cmdline;
        bool               nullifyStdio;		//是否关闭子进程STDIN，STDOUT，STDERR的显示
        bool               fuzzStdin;			//是否在STDIN上输入测试样例
        const char*        externalCommand;		//指定外部程序，使用外部程序生成fuzz文件，而不是内部变异引擎
        const char*        postExternalCommand;	//指定外部程序，由外部程序在文件变异后进行二次处理
        const char*        feedbackMutateCommand;	//指定外部程序，由具有有效覆盖率反馈的外部程序对文件进行变异
        bool               netDriver;			//是否使用netdriver (libhfnetdriver/)。在大多数情况下，
        										//它将通过二进制签名自动检测
        bool               persistent;			//使用persistent模式的模糊测试
        uint64_t           asLimit;				//MiB 中的每个进程 RLIMIT_AS（默认值：0 [无限制]）
        uint64_t           rssLimit;			/*MiB 中的每个进程 RLIMIT_RSS（默认值：0 [无限制]）。
        										如果使用，它还会设置 *SAN 的 soft_rss_limit_mb*/
        uint64_t           dataLimit;			//MiB 中的每个进程 RLIMIT_DATA（默认值：0 [无限制]）
        uint64_t           coreLimit;			//MiB 中的每个进程 RLIMIT_CORE（默认值：0 [不产生核心]）
        uint64_t           stackLimit;			//MiB 中的每个进程 RLIMIT_STACK（默认值：0 [默认限制]）
        bool               clearEnv;			//执行被fuzz程序之前清除所有环境变量
        char*              env_ptrs[128];		//指定额外的环境变量
        char               env_vals[128][4096];
        sigset_t           waitSigSet;
    } exe;
    struct {
        time_t  timeStart;
        time_t  runEndTime;						//这个模糊会话将持续的秒数(默认值:0[无限制])
        time_t  tmOut;							//进程超时检查时间
        time_t  lastCovUpdate;
        int64_t timeOfLongestUnitUSecs;
        bool    tmoutVTALRM;					//使用 SIGVTALRM 终止超时进程（默认：使用 SIGKILL）
    } timing;
    struct {
        struct {
            uint8_t val[512];
            size_t  len;
        } dictionary[8192];
        size_t      dictionaryCnt;
        const char* dictionaryFile;				//字典文件路径(用于帮助Fuzzer识别语法关键字)
        size_t      mutationsMax;				//模糊迭代次数（默认值：0 [无限制]）
        unsigned    mutationsPerRun;			//每次运行的最大突变数（默认值：6）
        size_t      maxInputSz;					//测试文件中最大大小
    } mutate;
    struct {
        bool    useScreen;						//是否使用 ANSI 控制台
        char    cmdline_txt[65];				//进程命令行
        int64_t lastDisplayUSecs;
    } display;									//honggfuzz控制台结构体
    struct {
        bool        useVerifier;				//是否启用崩溃验证器
        bool        exitUponCrash;				//产生第一次崩溃时退出
        uint8_t     exitCodeUponCrash;			//产生第一次崩溃时使用的退出代码（exit code，比如return 0）
        const char* reportFile;					//report文件，将report写入此文件（默认值：'<workdir>/HONGGFUZZ.REPORT.TXT'）
        size_t      dynFileIterExpire;
        bool        only_printable;				//是否只生成可打印的输入
        bool        minimize;					//最小化输入语料库。
        										//如果不使用 --output，
        										//它很可能会删除一些语料库文件（从 --input 目录）！
        bool        switchingToFDM;
    } cfg;										//配置结构体
    struct {
        bool enable;						//是否启用地址消杀器
        bool del_report;					//是否禁用地址消杀器报告
    } sanitizer;
    struct {
        fuzzState_t     state;
        feedback_t*     covFeedbackMap;
        int             covFeedbackFd;
        cmpfeedback_t*  cmpFeedbackMap;
        int             cmpFeedbackFd;
        bool            cmpFeedback;		//??使用模糊程序中的常量整数/字符串值通过动态字典来破坏输入文件(默认值:true)
		
        const char*     blocklistFile;		//??Stackhashes 黑名单文件（每行一个条目）
        uint64_t*       blocklist;
        size_t          blocklistCnt;
        bool            skipFeedbackOnTimeout;		//如果进程超时则跳过反馈（默认值：false）
        uint64_t        maxCov[4];
        dynFileMethod_t dynFileMethod;		//运行模式
        hwcnt_t         hwCnts;
    } feedback;
    struct {
        size_t mutationsCnt;
        size_t crashesCnt;
        size_t uniqueCrashesCnt;
        size_t verifiedCrashesCnt;
        size_t blCrashesCnt;
        size_t timeoutedCnt;
    } cnts;
    struct {
        bool enabled;							//是否通过socket进行模糊测试
        int  serverSocket;
        int  clientSocket;
    } socketFuzzer;
    struct {
        pthread_rwlock_t dynfileq;
        pthread_mutex_t  feedback;
        pthread_mutex_t  report;
        pthread_mutex_t  state;
        pthread_mutex_t  input;
        pthread_mutex_t  timing;
    } mutex;

    /* For the Linux code */
    struct {
        int         exeFd;
        uint64_t    dynamicCutOffAddr;				//忽略 IP 高于此地址的 perf 事件
        bool        disableRandomization;			//是否禁用ASLR随机化，可能对MSAN有用
        void*       ignoreAddr;						//地址限制(来自si.si_addr)低于此限制不报告崩溃，(默认值:0)
        const char* symsBlFile;
        char**      symsBl;
        size_t      symsBlCnt;
        const char* symsWlFile;
        char**      symsWl;
        size_t      symsWlCnt;
        uintptr_t   cloneFlags;
        tristate_t  useNetNs;						//使用Linux NET命名空间隔离(yes/no/maybe [default:no])
        bool        kernelOnly;						//使用 Intel PT 和 Intel BTS 收集Kernel-Only的覆盖率
        bool        useClone;
    } arch_linux;
    /* For the NetBSD code */
    struct {
        void*       ignoreAddr;						//地址限制(来自si.si_addr)低于此限制不报告崩溃，(默认值:0)
        const char* symsBlFile;
        char**      symsBl;
        size_t      symsBlCnt;
        const char* symsWlFile;
        char**      symsWl;
        size_t      symsWlCnt;
    } arch_netbsd;
} honggfuzz_t;

typedef enum {
    _HF_RS_UNKNOWN                   = 0,
    _HF_RS_WAITING_FOR_INITIAL_READY = 1,
    _HF_RS_WAITING_FOR_READY         = 2,
    _HF_RS_SEND_DATA                 = 3,
} runState_t;

typedef struct {
    honggfuzz_t* global;
    pid_t        pid;
    int64_t      timeStartedUSecs;
    char         crashFileName[PATH_MAX];
    uint64_t     pc;
    uint64_t     backtrace;
    uint64_t     access;
    int          exception;
    char         report[_HF_REPORT_SIZE];
    bool         mainWorker;
    unsigned     mutationsPerRun;
    dynfile_t*   dynfile;
    bool         staticFileTryMore;
    uint32_t     fuzzNo;
    int          persistentSock;
    runState_t   runState;
    bool         tmOutSignaled;
    char*        args[_HF_ARGS_MAX + 1];
    int          perThreadCovFeedbackFd;
    unsigned     triesLeft;
    dynfile_t*   current;
#if !defined(_HF_ARCH_DARWIN)
    timer_t timerId;
#endif    // !defined(_HF_ARCH_DARWIN)
    hwcnt_t hwCnts;

    struct {
        /* For Linux code */
        uint8_t* perfMmapBuf;
        uint8_t* perfMmapAux;
        int      cpuInstrFd;
        int      cpuBranchFd;
        int      cpuIptBtsFd;
    } arch_linux;
} run_t;

#endif
