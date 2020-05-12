# self-checksumming

![alt text](https://github.com/mr-ma/self-checksumming/blob/master/process/OH-SC-Process.pdf)

## Compiling obfuscation protections
```bash
mkdir obfuscation && cd obfuscation
git clone -b cfg_indirection https://github.com/toizi/Obfuscator-LLVM.git
cd Obfuscator-LLVM
mkdir -p build && cd build
cmake -G Ninja -DCMAKE_BUILD_TYPE=Release ..
cmake --build . --target LLVMObfuscation
cmake --build . --target clang
cmake --build . --target opt
```

## Protecting the samples
Make sure you also have clang-6.0 installed.

To protect the mibench samples, use the `batch_compile_mibench.py` script.
Sample invocation that compiles all programs in `samples/protection_dataset`
with `obfuscations x {0, 10, 20}% coverage`. The temporary build artifacts and
logs will be stored in the `mibench_build` directory.
```
./batch_compile_mibench.py samples/protection_dataset -ob flatten.0 -ob virt.0 -ob opaque.0 -ob subst.0 -ob indir.0 -ob flatten.10 -ob virt.10 -ob opaque.10 -ob subst.10 -ob indir.10 -ob flatten.20 -ob virt.20 -ob opaque.20 -ob subst.20 -ob indir.20 -ob none.0 --seeds=11 --connectivity=3 -o samples/protection_dataset_bin --build-dir mibench_build -j3
```
