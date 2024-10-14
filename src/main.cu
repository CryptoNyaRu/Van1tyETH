#if defined(_WIN64)
    #define WIN32_NO_STATUS
    #include <windows.h>
    #undef WIN32_NO_STATUS
#endif

#include <thread>
#include <cinttypes>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <queue>
#include <chrono>
#include <fstream>
#include <vector>

#include "secure_rand.h"
#include "structures.h"

#include "cpu_curve_math.h"
#include "cpu_keccak.h"
#include "cpu_math.h"

#include <cuda.h>
#include <cuda_runtime.h>
#include <cuda_runtime_api.h>
#include <device_launch_parameters.h>

#define OUTPUT_BUFFER_SIZE 10000

#define BLOCK_SIZE 256U
#define THREAD_WORK (1U << 8)

__constant__ CurvePoint thread_offsets[BLOCK_SIZE];
__constant__ CurvePoint addends[THREAD_WORK - 1];
__device__ uint64_t device_memory[2 + OUTPUT_BUFFER_SIZE * 3];

__device__ int count_zero_bytes(uint32_t x) {
    int n = 0;
    n += ((x & 0xFF) == 0);
    n += ((x & 0xFF00) == 0);
    n += ((x & 0xFF0000) == 0);
    n += ((x & 0xFF000000) == 0);
    return n;
}

__device__ int score_zero_bytes(Address a) {
    int n = 0;
    n += count_zero_bytes(a.a);
    n += count_zero_bytes(a.b);
    n += count_zero_bytes(a.c);
    n += count_zero_bytes(a.d);
    n += count_zero_bytes(a.e);
    return n;
}

__device__ int score_leading_zeros(Address a) {
    int n = __clz(a.a);
    if (n == 32) {
        n += __clz(a.b);

        if (n == 64) {
            n += __clz(a.c);

            if (n == 96) {
                n += __clz(a.d);

                if (n == 128) {
                    n += __clz(a.e);
                }
            }
        }
    }

    return n >> 3;
}

#ifdef __linux__
    #define atomicMax_ul(a, b) atomicMax((unsigned long long*)(a), (unsigned long long)(b))
    #define atomicAdd_ul(a, b) atomicAdd((unsigned long long*)(a), (unsigned long long)(b))
#else
    #define atomicMax_ul(a, b) atomicMax(a, b)
    #define atomicAdd_ul(a, b) atomicAdd(a, b)
#endif

__device__ void handle_output(int score_method, Address a, uint64_t key, bool inv) {
    int score = 0;
    if (score_method == 0) { score = score_leading_zeros(a); }
    else if (score_method == 1) { score = score_zero_bytes(a); }

    if (score >= device_memory[1]) {
        atomicMax_ul(&device_memory[1], score);
        if (score >= device_memory[1]) {
            uint32_t idx = atomicAdd_ul(&device_memory[0], 1);
            if (idx < OUTPUT_BUFFER_SIZE) {
                device_memory[2 + idx] = key;
                device_memory[OUTPUT_BUFFER_SIZE + 2 + idx] = score;
                device_memory[OUTPUT_BUFFER_SIZE * 2 + 2 + idx] = inv;
            }
        }
    }
}

__device__ void handle_output2(int score_method, Address a, uint64_t key) {
    int score = 0;
    if (score_method == 0) { score = score_leading_zeros(a); }
    else if (score_method == 1) { score = score_zero_bytes(a); }

    if (score >= device_memory[1]) {
        atomicMax_ul(&device_memory[1], score);
        if (score >= device_memory[1]) {
            uint32_t idx = atomicAdd_ul(&device_memory[0], 1);
            if (idx < OUTPUT_BUFFER_SIZE) {
                device_memory[2 + idx] = key;
                device_memory[OUTPUT_BUFFER_SIZE + 2 + idx] = score;
            }
        }
    }
}

#include "address.h"
#include "contract_address.h"
#include "contract_address2.h"

int global_max_score = 0;
std::mutex global_max_score_mutex;
uint32_t GRID_SIZE = 1U << 15;

struct Message {
    uint64_t time;

    int status;
    int device_index;
    cudaError_t error;

    double speed;
    int results_count;
    _uint256* results;
    int* scores;
};

std::queue<Message> message_queue;
std::mutex message_queue_mutex;


#define gpu_assert(call) { \
    cudaError_t e = call; \
    if (e != cudaSuccess) { \
        message_queue_mutex.lock(); \
        message_queue.push(Message{milliseconds(), 1, device_index, e}); \
        message_queue_mutex.unlock(); \
        if (thread_offsets_host != 0) { cudaFreeHost(thread_offsets_host); } \
        if (device_memory_host != 0) { cudaFreeHost(device_memory_host); } \
        cudaDeviceReset(); \
        return; \
    } \
}

uint64_t milliseconds() {
    return (std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())).count();
}


void host_thread(int device, int device_index, int score_method, int mode, Address create2_factory, _uint256 bytecode) {
    uint64_t GRID_WORK = ((uint64_t)BLOCK_SIZE * (uint64_t)GRID_SIZE * (uint64_t)THREAD_WORK);

    CurvePoint* block_offsets = 0;
    CurvePoint* offsets = 0;
    CurvePoint* thread_offsets_host = 0;

    uint64_t* device_memory_host = 0;
    uint64_t* max_score_host;
    uint64_t* output_counter_host;
    uint64_t* output_buffer_host;
    uint64_t* output_buffer2_host;
    uint64_t* output_buffer3_host;

    gpu_assert(cudaSetDevice(device));

    gpu_assert(cudaHostAlloc(&device_memory_host, (2 + OUTPUT_BUFFER_SIZE * 3) * sizeof(uint64_t), cudaHostAllocDefault))
    output_counter_host = device_memory_host;
    max_score_host = device_memory_host + 1;
    output_buffer_host = max_score_host + 1;
    output_buffer2_host = output_buffer_host + OUTPUT_BUFFER_SIZE;
    output_buffer3_host = output_buffer2_host + OUTPUT_BUFFER_SIZE;

    output_counter_host[0] = 0;
    max_score_host[0] = 2;
    gpu_assert(cudaMemcpyToSymbol(device_memory, device_memory_host, 2 * sizeof(uint64_t)));
    gpu_assert(cudaDeviceSynchronize())


    if (mode == 0 || mode == 1) {
        gpu_assert(cudaMalloc(&block_offsets, GRID_SIZE * sizeof(CurvePoint)))
        gpu_assert(cudaMalloc(&offsets, (uint64_t)GRID_SIZE * BLOCK_SIZE * sizeof(CurvePoint)))
        thread_offsets_host = new CurvePoint[BLOCK_SIZE];
        gpu_assert(cudaHostAlloc(&thread_offsets_host, BLOCK_SIZE * sizeof(CurvePoint), cudaHostAllocWriteCombined))
    }

    _uint256 max_key;
    if (mode == 0 || mode == 1) {
        _uint256 GRID_WORK = cpu_mul_256_mod_p(cpu_mul_256_mod_p(_uint256{0, 0, 0, 0, 0, 0, 0, THREAD_WORK}, _uint256{0, 0, 0, 0, 0, 0, 0, BLOCK_SIZE}), _uint256{0, 0, 0, 0, 0, 0, 0, GRID_SIZE});
        max_key = _uint256{0x7FFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x5D576E73, 0x57A4501D, 0xDFE92F46, 0x681B20A0};
        max_key = cpu_sub_256(max_key, GRID_WORK);
        max_key = cpu_sub_256(max_key, _uint256{0, 0, 0, 0, 0, 0, 0, THREAD_WORK});
        max_key = cpu_add_256(max_key, _uint256{0, 0, 0, 0, 0, 0, 0, 2});
    } else if (mode == 2) {
        max_key = _uint256{0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF};
    }

    _uint256 base_random_key{0, 0, 0, 0, 0, 0, 0, 0};
    _uint256 random_key_increment{0, 0, 0, 0, 0, 0, 0, 0};
    int status;
    if (mode == 0 || mode == 1) {
        status = generate_secure_random_key(base_random_key, max_key, 255);
        random_key_increment = cpu_mul_256_mod_p(cpu_mul_256_mod_p(uint32_to_uint256(BLOCK_SIZE), uint32_to_uint256(GRID_SIZE)), uint32_to_uint256(THREAD_WORK));
    } else if (mode == 2) {
        status = generate_secure_random_key(base_random_key, max_key, 256);
        random_key_increment = cpu_mul_256_mod_p(cpu_mul_256_mod_p(uint32_to_uint256(BLOCK_SIZE), uint32_to_uint256(GRID_SIZE)), uint32_to_uint256(THREAD_WORK));
        base_random_key.h &= ~(THREAD_WORK - 1);
    }

    if (status) {
        message_queue_mutex.lock();
        message_queue.push(Message{milliseconds(), 10 + status});
        message_queue_mutex.unlock();
        return;
    }
    _uint256 random_key = base_random_key;

    if (mode == 0 || mode == 1) {
        CurvePoint* addends_host = new CurvePoint[THREAD_WORK - 1];
        CurvePoint p = G;
        for (int i = 0; i < THREAD_WORK - 1; i++) {
            addends_host[i] = p;
            p = cpu_point_add(p, G);
        }
        gpu_assert(cudaMemcpyToSymbol(addends, addends_host, (THREAD_WORK - 1) * sizeof(CurvePoint)))
        delete[] addends_host;

        CurvePoint* block_offsets_host = new CurvePoint[GRID_SIZE];
        CurvePoint block_offset = cpu_point_multiply(G, _uint256{0, 0, 0, 0, 0, 0, 0, THREAD_WORK * BLOCK_SIZE});
        p = G;
        for (int i = 0; i < GRID_SIZE; i++) {
            block_offsets_host[i] = p;
            p = cpu_point_add(p, block_offset);
        }
        gpu_assert(cudaMemcpy(block_offsets, block_offsets_host, GRID_SIZE * sizeof(CurvePoint), cudaMemcpyHostToDevice))
        delete[] block_offsets_host;
    }

    if (mode == 0 || mode == 1) {
        cudaStream_t streams[2];
        gpu_assert(cudaStreamCreate(&streams[0]))
        gpu_assert(cudaStreamCreate(&streams[1]))
        
        _uint256 previous_random_key = random_key;
        bool first_iteration = true;
        uint64_t start_time;
        uint64_t end_time;
        double elapsed;

        while (true) {
            if (!first_iteration) {
                if (mode == 0) {
                    gpu_address_work<<<GRID_SIZE, BLOCK_SIZE, 0, streams[0]>>>(score_method, offsets);
                } else {
                    gpu_contract_address_work<<<GRID_SIZE, BLOCK_SIZE, 0, streams[0]>>>(score_method, offsets);
                }
            }

            if (!first_iteration) {
                previous_random_key = random_key;
                random_key = cpu_add_256(random_key, random_key_increment);
                if (gte_256(random_key, max_key)) {
                    random_key = cpu_sub_256(random_key, max_key);
                }
            }
            CurvePoint thread_offset = cpu_point_multiply(G, _uint256{0, 0, 0, 0, 0, 0, 0, THREAD_WORK});
            CurvePoint p = cpu_point_multiply(G, cpu_add_256(_uint256{0, 0, 0, 0, 0, 0, 0, THREAD_WORK - 1}, random_key));
            for (int i = 0; i < BLOCK_SIZE; i++) {
                thread_offsets_host[i] = p;
                p = cpu_point_add(p, thread_offset);
            }
            gpu_assert(cudaMemcpyToSymbolAsync(thread_offsets, thread_offsets_host, BLOCK_SIZE * sizeof(CurvePoint), 0, cudaMemcpyHostToDevice, streams[1]));
            gpu_assert(cudaStreamSynchronize(streams[1]))
            gpu_assert(cudaStreamSynchronize(streams[0]))

            if (!first_iteration) {
                end_time = milliseconds();
                elapsed = (end_time - start_time) / 1000.0;
            }
            start_time = milliseconds();

            gpu_address_init<<<GRID_SIZE/BLOCK_SIZE, BLOCK_SIZE, 0, streams[0]>>>(block_offsets, offsets);
            if (!first_iteration) {
                gpu_assert(cudaMemcpyFromSymbolAsync(device_memory_host, device_memory, (2 + OUTPUT_BUFFER_SIZE * 3) * sizeof(uint64_t), 0, cudaMemcpyDeviceToHost, streams[1]))
                gpu_assert(cudaStreamSynchronize(streams[1]))
            }
            if (!first_iteration) {
                global_max_score_mutex.lock();
                if (output_counter_host[0] != 0) {
                    if (max_score_host[0] > global_max_score) {
                        global_max_score = max_score_host[0];
                    } else {
                        max_score_host[0] = global_max_score;
                    }
                }
                global_max_score_mutex.unlock();

                double speed = GRID_WORK / elapsed / 1000000.0 * 2;
                if (output_counter_host[0] != 0) {
                    int valid_results = 0;

                    for (int i = 0; i < output_counter_host[0]; i++) {
                        if (output_buffer2_host[i] < max_score_host[0]) { continue; }
                        valid_results++;
                    }

                    if (valid_results > 0) {
                        _uint256* results = new _uint256[valid_results];
                        int* scores = new int[valid_results];
                        valid_results = 0;

                        for (int i = 0; i < output_counter_host[0]; i++) {
                            if (output_buffer2_host[i] < max_score_host[0]) { continue; }

                            uint64_t k_offset = output_buffer_host[i];
                            _uint256 k = cpu_add_256(previous_random_key, cpu_add_256(_uint256{0, 0, 0, 0, 0, 0, 0, THREAD_WORK}, _uint256{0, 0, 0, 0, 0, 0, (uint32_t)(k_offset >> 32), (uint32_t)(k_offset & 0xFFFFFFFF)}));

                            if (output_buffer3_host[i]) {
                                k = cpu_sub_256(N, k);
                            }
                
                            int idx = valid_results++;
                            results[idx] = k;
                            scores[idx] = output_buffer2_host[i];
                        }

                        message_queue_mutex.lock();
                        message_queue.push(Message{end_time, 0, device_index, cudaSuccess, speed, valid_results, results, scores});
                        message_queue_mutex.unlock();
                    } else {
                        message_queue_mutex.lock();
                        message_queue.push(Message{end_time, 0, device_index, cudaSuccess, speed, 0});
                        message_queue_mutex.unlock();
                    }
                } else {
                    message_queue_mutex.lock();
                    message_queue.push(Message{end_time, 0, device_index, cudaSuccess, speed, 0});
                    message_queue_mutex.unlock();
                }
            }

            if (!first_iteration) {
                output_counter_host[0] = 0;
                gpu_assert(cudaMemcpyToSymbolAsync(device_memory, device_memory_host, sizeof(uint64_t), 0, cudaMemcpyHostToDevice, streams[1]));
                gpu_assert(cudaStreamSynchronize(streams[1]))
            }
            gpu_assert(cudaStreamSynchronize(streams[0]))
            first_iteration = false;
        }
    }

    if (mode == 2) {
        while (true) {
            uint64_t start_time = milliseconds();
            gpu_contract2_address_work<<<GRID_SIZE, BLOCK_SIZE>>>(score_method, create2_factory, random_key, bytecode);

            gpu_assert(cudaDeviceSynchronize())
            gpu_assert(cudaMemcpyFromSymbol(device_memory_host, device_memory, (2 + OUTPUT_BUFFER_SIZE * 3) * sizeof(uint64_t)))

            uint64_t end_time = milliseconds();
            double elapsed = (end_time - start_time) / 1000.0;

            global_max_score_mutex.lock();
            if (output_counter_host[0] != 0) {
                if (max_score_host[0] > global_max_score) {
                    global_max_score = max_score_host[0];
                } else {
                    max_score_host[0] = global_max_score;
                }
            }
            global_max_score_mutex.unlock();

            double speed = GRID_WORK / elapsed / 1000000.0;
            if (output_counter_host[0] != 0) {
                int valid_results = 0;

                for (int i = 0; i < output_counter_host[0]; i++) {
                    if (output_buffer2_host[i] < max_score_host[0]) { continue; }
                    valid_results++;
                }

                if (valid_results > 0) {
                    _uint256* results = new _uint256[valid_results];
                    int* scores = new int[valid_results];
                    valid_results = 0;

                    for (int i = 0; i < output_counter_host[0]; i++) {
                        if (output_buffer2_host[i] < max_score_host[0]) { continue; }

                        uint64_t k_offset = output_buffer_host[i];
                        _uint256 k = cpu_add_256(random_key, _uint256{0, 0, 0, 0, 0, 0, (uint32_t)(k_offset >> 32), (uint32_t)(k_offset & 0xFFFFFFFF)});
            
                        int idx = valid_results++;
                        results[idx] = k;
                        scores[idx] = output_buffer2_host[i];
                    }

                    message_queue_mutex.lock();
                    message_queue.push(Message{end_time, 0, device_index, cudaSuccess, speed, valid_results, results, scores});
                    message_queue_mutex.unlock();
                } else {
                    message_queue_mutex.lock();
                    message_queue.push(Message{end_time, 0, device_index, cudaSuccess, speed, 0});
                    message_queue_mutex.unlock();
                }
            } else {
                message_queue_mutex.lock();
                message_queue.push(Message{end_time, 0, device_index, cudaSuccess, speed, 0});
                message_queue_mutex.unlock();
            }

            random_key = cpu_add_256(random_key, random_key_increment);

            output_counter_host[0] = 0;
            gpu_assert(cudaMemcpyToSymbol(device_memory, device_memory_host, sizeof(uint64_t)));
        }
    }
}


void print_speeds(int num_devices, int* device_ids, double* speeds) {
    double total = 0.0;
    for (int i = 0; i < num_devices; i++) {
        total += speeds[i];
    }

    printf("Total: %.2fM/s", total);
    for (int i = 0; i < num_devices; i++) {
        printf("    Device %d: %.2fM/s", device_ids[i], speeds[i]);
    }
}


int main(int argc, char *argv[]) {
    int num_devices = 0;
    int device_ids[10];

    int score_method = -1; // 0 = leading zeroes, 1 = zeros

    int mode = -1; // 0 = EOA, 1 = CREATE, 2 = CREATE2
    char* input_create2_factory = 0;
    char* input_bytecode_path = 0;
    bool usingC0ntractcharm = false;

    for (int i = 1; i < argc;) {
        if (strcmp(argv[i], "--device") == 0 || strcmp(argv[i], "-d") == 0) {
            device_ids[num_devices++] = atoi(argv[i + 1]);
            i += 2;
        } else if (strcmp(argv[i], "--work-scale") == 0 || strcmp(argv[i], "-w") == 0) {
            GRID_SIZE = 1U << atoi(argv[i + 1]);
            i += 2;
        } else if (strcmp(argv[i], "--leading-zeros") == 0 || strcmp(argv[i], "-lz") == 0) {
            score_method = 0;
            i++;
        } else if (strcmp(argv[i], "--zeros") == 0 || strcmp(argv[i], "-z") == 0) {
            score_method = 1;
            i++;
        } else if (strcmp(argv[i], "--eoa") == 0 || strcmp(argv[i], "-e") == 0) {
            mode = 0;
            i++;
        } else if (strcmp(argv[i], "--create") == 0 || strcmp(argv[i], "-c") == 0) {
            mode = 1;
            i++;
        } else if (strcmp(argv[i], "--create2") == 0 || strcmp(argv[i], "-c2") == 0) {
            mode = 2;
            input_create2_factory = argv[i + 1];
            input_bytecode_path = argv[i + 2];
            if (!input_create2_factory) {
                printf("You must specify a CREATE2 factory when using -c2(\"-c2 <factory> <bytecode_path>\")\n");
                return 1;
            }
            if (strlen(input_create2_factory) != 40 && strlen(input_create2_factory) != 42) {
                printf("The CREATE2 factory must be 40 characters long\n");
                return 1;
            }
            if (!input_bytecode_path) {
                printf("You must specify contract bytecode path when using -c2(\"-c2 <factory> <bytecode_path>\")\n");
                return 1;
            }
            i += 3;
        } else if (strcmp(argv[i], "--c0ntractcharm") == 0 || strcmp(argv[i], "-cc") == 0) {
            mode = 2;
            input_create2_factory = argv[i + 1];
            if (!input_create2_factory) {
                printf("You must specify the C0ntractcharm address when using -cc(\"-cc <address>\")\n");
                return 1;
            }
            if (strlen(input_create2_factory) != 40 && strlen(input_create2_factory) != 42) {
                printf("The C0ntractcharm address must be 40 characters long\n");
                return 1;
            }
            usingC0ntractcharm = true;
            i += 2;
        } else {
            i++;
        }
    }

    if (num_devices == 0) {
        printf("No device is specified(\"-d 0\" to use device 0)\n");
        return 1;
    }
    for (int i = 0; i < num_devices; i++) {
        cudaError_t e = cudaSetDevice(device_ids[i]);
        if (e != cudaSuccess) {
            printf("Could not detect device: %d\n", device_ids[i]);
            return 1;
        }
    }

    if (score_method == -1) {
        printf("No scoring method is specified(\"-lz\" for leading zeros, \"-z\" for zeros)\n");
        return 1;
    }

    if (mode == -1) {
        printf("No mode is specified(\"-e\" for EOA, \"-c\" for CREATE Contract, \"-c2\" for CREATE2 Contract)\", \"-cc <address>\" for C0ntractcharm)\n");
        return 1;
    }
    if (mode != 0 && mode != 1 && mode != 2) {
        printf("Mode is invalid: %d\n", mode);
        return 1;
    }

    #define nothex(n) ((n < 48 || n > 57) && (n < 65 || n > 70) && (n < 97 || n > 102))
    _uint256 bytecode_hash;
    if (mode == 2) {
        if (usingC0ntractcharm) {
            //0x6000600060006000335afa3d600060003e3d6000f3 21 bytes
            uint8_t* bytecode = new uint8_t[21];
            if (bytecode == 0) {
                printf("Failed to allocate memory");
                return 1;
            }
            bytecode[0] = 0x60;
            bytecode[1] = 0x00;
            bytecode[2] = 0x60;
            bytecode[3] = 0x00;
            bytecode[4] = 0x60;
            bytecode[5] = 0x00;
            bytecode[6] = 0x60;
            bytecode[7] = 0x00;
            bytecode[8] = 0x33;
            bytecode[9] = 0x5a;
            bytecode[10] = 0xfa;
            bytecode[11] = 0x3d;
            bytecode[12] = 0x60;
            bytecode[13] = 0x00;
            bytecode[14] = 0x60;
            bytecode[15] = 0x00;
            bytecode[16] = 0x3e;
            bytecode[17] = 0x3d;
            bytecode[18] = 0x60;
            bytecode[19] = 0x00;
            bytecode[20] = 0xf3;

            bytecode_hash = cpu_full_keccak(bytecode, 21);
            delete[] bytecode;
        } else {
            std::ifstream infile(input_bytecode_path, std::ios::binary);
            if (!infile.is_open()) {
                printf("Failed to read the bytecode file\n");
                return 1;
            }

            int file_size = 0;
            {
                infile.seekg(0, std::ios::end);
                std::streampos file_size_ = infile.tellg();
                infile.seekg(0, std::ios::beg);
                file_size = file_size_ - infile.tellg();
            }

            if (file_size & 1) {
                printf("The length of bytecode in file is invalid\n");
                return 1;
            }

            uint8_t* bytecode = new uint8_t[24576];
            if (bytecode == 0) {
                printf("Failed to allocate memory");
                return 1;
            }

            char byte[2];
            bool prefix = false;
            for (int i = 0; i < (file_size >> 1); i++) {
                infile.read((char*)&byte, 2);
                if (i == 0) {
                    prefix = byte[0] == '0' && byte[1] == 'x';
                    if ((file_size >> 1) > (prefix ? 24577 : 24576)) {
                        printf("The bytecode in file is invalid\n");
                        delete[] bytecode;
                        return 1;
                    }
                    if (prefix) { continue; }
                }

                if (nothex(byte[0]) || nothex(byte[1])) {
                    printf("The bytecode in file is invalid\n");
                    delete[] bytecode;
                    return 1;
                }

                bytecode[i - prefix] = (uint8_t)strtol(byte, 0, 16);
            }
            bytecode_hash = cpu_full_keccak(bytecode, (file_size >> 1) - prefix);
            delete[] bytecode;
        }
    }

    Address create2_factory;
    if (mode == 2) {
        if (strlen(input_create2_factory) == 42) {
            input_create2_factory += 2;
        }
        char substr[9];

        #define round(i, offset) \
        strncpy(substr, input_create2_factory + offset * 8, 8); \
        if (nothex(substr[0]) || nothex(substr[1]) || nothex(substr[2]) || nothex(substr[3]) || nothex(substr[4]) || nothex(substr[5]) || nothex(substr[6]) || nothex(substr[7])) { \
            printf("The CREATE2 factory is invalid\n"); \
            return 1; \
        } \
        create2_factory.i = strtoull(substr, 0, 16);

        round(a, 0)
        round(b, 1)
        round(c, 2)
        round(d, 3)
        round(e, 4)

        #undef round
    }
    #undef nothex

    std::vector<std::thread> threads;
    uint64_t global_start_time = milliseconds();
    for (int i = 0; i < num_devices; i++) {
        std::thread th(host_thread, device_ids[i], i, score_method, mode, create2_factory, bytecode_hash);
        threads.push_back(move(th));
    }

    double speeds[100];
    while(true) {
        message_queue_mutex.lock();
        if (message_queue.size() == 0) {
            message_queue_mutex.unlock();
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        } else {
            while (!message_queue.empty()) {
                Message m = message_queue.front();
                message_queue.pop();

                int device_index = m.device_index;

                if (m.status == 0) {
                    speeds[device_index] = m.speed;

                    printf("\r");
                    if (m.results_count != 0) {
                        Address* addresses = new Address[m.results_count];
                        for (int i = 0; i < m.results_count; i++) {
                            if (mode == 0) {
                                CurvePoint p = cpu_point_multiply(G, m.results[i]);
                                addresses[i] = cpu_calculate_address(p.x, p.y);
                            } else if (mode == 1) {
                                CurvePoint p = cpu_point_multiply(G, m.results[i]);
                                addresses[i] = cpu_calculate_contract_address(cpu_calculate_address(p.x, p.y));
                            } else if (mode == 2) {
                                addresses[i] = cpu_calculate_contract_address2(create2_factory, m.results[i], bytecode_hash);
                            }
                        }

                        for (int i = 0; i < m.results_count; i++) {
                            _uint256 k = m.results[i];
                            int score = m.scores[i];
                            Address a = addresses[i];
                            uint64_t time = (m.time - global_start_time) / 1000;

                            if (mode == 0 || mode == 1) {
                                printf("Elapsed: %06u    Score: %02u    Private Key: 0x%08x%08x%08x%08x%08x%08x%08x%08x    Address: 0x%08x%08x%08x%08x%08x\n", (uint32_t)time, score, k.a, k.b, k.c, k.d, k.e, k.f, k.g, k.h, a.a, a.b, a.c, a.d, a.e);
                            } else if (mode == 2) {
                                printf("Elapsed: %06u    Score: %02u    Salt: 0x%08x%08x%08x%08x%08x%08x%08x%08x    Address: 0x%08x%08x%08x%08x%08x\n", (uint32_t)time, score, k.a, k.b, k.c, k.d, k.e, k.f, k.g, k.h, a.a, a.b, a.c, a.d, a.e);
                            }
                        }

                        delete[] addresses;
                        delete[] m.results;
                        delete[] m.scores;
                    }
                    print_speeds(num_devices, device_ids, speeds);
                    fflush(stdout);
                } else if (m.status == 1) {
                    printf("\rCuda error %d on device %d. Device will halt work.\n", m.error, device_ids[device_index]);
                    print_speeds(num_devices, device_ids, speeds);
                    fflush(stdout);
                } else if (m.status == 11) {
                    printf("\rError from BCryptGenRandom. Device %d will halt work.", device_ids[device_index]);
                    print_speeds(num_devices, device_ids, speeds);
                    fflush(stdout);
                } else if (m.status == 12) {
                    printf("\rError while reading from /dev/urandom. Device %d will halt work.", device_ids[device_index]);
                    print_speeds(num_devices, device_ids, speeds);
                    fflush(stdout);
                } else if (m.status == 13) {
                    printf("\rError while opening /dev/urandom. Device %d will halt work.", device_ids[device_index]);
                    print_speeds(num_devices, device_ids, speeds);
                    fflush(stdout);
                } else if (m.status == 100) {
                    printf("\Failed to allocate memory. Device %d will halt work.", device_ids[device_index]);
                }
                // break;
            }
            message_queue_mutex.unlock();
        }
    }
}