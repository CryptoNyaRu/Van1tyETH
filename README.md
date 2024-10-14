## 设备要求

- Van1tyETH 仅支持  CUDA 计算能力  >= 5.2 的 GPU(≈ GTX 950): [CUDA 计算能力列表](https://developer.nvidia.com/cuda-gpus)
- 如果你的设备不支持 CUDA 或 CUDA 计算能力不足, 那么建议你使用 1inch 的 [profanity2](https://github.com/1inch/profanity2) 以及 [ERADICATE2](https://github.com/johguse/ERADICATE2)

## 使用方法

```
./Van1tyETH [PARAMETERS]
    Performance:
         -d (--device) <device_number>               Use device <device_number> (Add one for each device for multi-gpu)
         -w (--work-scale) <num>                     Defaults to 15. Scales the work done in each kernel. If your GPU finishes kernels within a few seconds, you may benefit from increasing this number.

    Scoring methods:
        -lz (--leading-zeros)                        Count zero bytes at the start of address
         -z (--zeros)                                Count zero bytes anywhere in address

    Modes:
         -e (--eoa)                                  Search for EOA addresses
         -c (--create)                               Search for contract addresses generated with CREATE(nonce=0)
        -c2 (--create2) <factory> <bytecode_path>    Search for contract addresses for CREATE2
        -cc (--c0ntractcharm) <address>              Search for contract addresses for C0ntractCharm
```

## 注意事项

- Van1tyETH 可以直接为 [C0ntractCharm](https://github.com/CryptoNyaRu/C0ntractCharm) 计算 Salt, 推荐配合使用
- 与 [profanity](https://github.com/johguse/profanity) 不同, Van1tyETH **使用足够强度的随机源初始化私钥**, 因此由初始私钥迭代得到的靓号地址可以被认为是安全的
- **在生成 EOA 地址时, 任何可以接触设备的人都可以看到终端内输出的私钥!!! 因此如果你需要租用 GPU 服务器进行生成, 那么建议你使用 1inch 的 [profanity2](https://github.com/1inch/profanity2)**
- **请不要使用别人编译好的可执行文件, 务必自行编译!!!** 
- **请不要使用别人编译好的可执行文件, 务必自行编译!!!** 
- **请不要使用别人编译好的可执行文件, 务必自行编译!!!** 

## 鸣谢

- Van1tyETH 基于 [vanity-eth-address](https://github.com/MrSpike63/vanity-eth-address), 在此基础上修复了部分 bug, 并添加了对 [C0ntractCharm](https://github.com/CryptoNyaRu/C0ntractCharm) 的支持
- 按照原项目 AGPL-3.0 协议的要求进行开源, 感谢原作者的卓越贡献
