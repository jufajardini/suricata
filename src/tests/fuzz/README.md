# How to run fuzzing?

There are several ways of running Suricata fuzzers, with general steps described bellow.
The preferred way, especially if you want to reproduce a CIFuzz failure, is oss-fuzz (as
that is how contributions are checked against, on GitHub, and how Suricata is continously
fuzzed.

## 1. With oss-fuzz

1.1. install docker (see https://docs.docker.com/engine/install/)

1.2. run:

```
git clone --depth 1 https://github.com/google/oss-fuzz
```
1.3. change directory into cloned repository:

```
cd oss-fuzz
```
1.4. To build Suricata docker image, run:

```
python infra/helper.py build_image suricata
```
1.5. To generate the fuzz targets, run the following command, choosing between `address` or `undefined` as sanitizer option:

```
python infra/helper.py build_fuzzers --sanitizer address suricata
```

1.6. Check what fuzz targes are available with:

```
ls build/out/suricata/fuzz_*
```
1.7. Run a fuzz target with (use ``fuzz_siginit`` or replace that with any of the available fuzz targets):

```
python infra/helper.py run_fuzzer suricata fuzz_siginit
```

Steps 1.1 and 1.2 only have to be performed once. After cloning oss-fuzz,
just make sure that it is up-to-date before fuzzing with it.
Step 1.4 would have to be repeated if the Suricata repository has been 
updated and you want to build an image with those changes.

### Optional steps

(These can be performed after the previous steps)

1.8. To generate coverage with oss-fuzz for a specific fuzzer:

1.8.1. install gsutil. Follow instructions at https://cloud.google.com/storage/docs/gsutil_install

1.8.2. [optional] to get the latest coverage tools, run:

```
python infra/helper.py pull_images
```

1.8.3. create a directory to locally store corpus that will be used by the coverage command:

```
mkdir your-tmp-dir
```

1.8.4. run the fuzz target passing the created dir:

```
python infra/helper.py run_fuzzer --corpus-dir=path/to/your-tmp-dir suricata <fuzz_target>
```

1.8.5. build the fuzzers

```
python infra/helper.py build_fuzzers --sanitizer coverage suricata
```

1.8.6. generate coverage for the specific fuzz target, indicating where to find the local corpus::

```
python infra/helper.py coverage suricata --fuzz-target=<fuzz_target> --corpus-dir=path/to/your-tmp-dir
```
After running that last command, the script will host a local code coverage report that can be accessed via browser.


## 2. With libfuzzer

To compile the fuzz targets, you can do the following.
These flags are just one option and you are welcome to change them when you know what you are doing.

```
export CFLAGS="-g -O1 -fno-omit-frame-pointer -gline-tables-only \
-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=address -fsanitize-address-use-after-scope \
-fsanitize=fuzzer-no-link"
export CXXFLAGS="-g -O1 -fno-omit-frame-pointer -gline-tables-only \
-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION -fsanitize=address -fsanitize-address-use-after-scope -fsanitize=fuzzer-no-link -stdlib=libc++"
export RUSTFLAGS="--cfg fuzzing -Cdebuginfo=1 -Cforce-frame-pointers"
export RUSTFLAGS="$RUSTFLAGS -Cpasses=sancov -Cllvm-args=-sanitizer-coverage-level=4 \
-Cllvm-args=-sanitizer-coverage-trace-compares -Cllvm-args=-sanitizer-coverage-inline-8bit-counters \
-Cllvm-args=-sanitizer-coverage-trace-geps -Cllvm-args=-sanitizer-coverage-prune-blocks=0 \
-Cllvm-args=-sanitizer-coverage-pc-table -Clink-dead-code -Cllvm-args=-sanitizer-coverage-stack-depth"
export LIB_FUZZING_ENGINE=-fsanitize=fuzzer
export CC=clang
export CXX=clang++
./configure --enable-fuzztargets
make
```

**Note**
> Try first without exporting `RUSTFLAGS` as these seem to generate more errors.
> Once you get things to work without them, move on to trying to have the Rust side of Suricata fuzzable.
> If build fails, try removing `-stdlib=libc++` from your `CXXFLAGS` and configuring again.

You can specify other sanitizers here such as undefined and memory

Then you can run a target:
```
./src/fuzz_target_x your_libfuzzer_options
```

Where target_x is on file in `ls ./src/fuzz_*`

**Note**

> If your clang does not support the compile flag "-fsanitize=fuzzer" (MacOS), you can run these
> same commands but you need first to install libfuzzer as libFuzzingEngine and you need to add
> `export LIB_FUZZING_ENGINE=/path/to/libFuzzer.a` before calling configure command

To compile libFuzzer, you can do the following
```
svn co http://llvm.org/svn/llvm-project/compiler-rt/trunk/lib/fuzzer
cd fuzzer
./build.sh
```


## With afl

To compile the fuzz targets, you simply need to run
```
CC=afl-gcc ./configure --enable-fuzztargets
CC=afl-gcc make
```
You can rather use afl-clang if needed. Then you can run afl as usual with each of
the fuzz targets in ./src/.libs/
```
afl-fuzz your_afl_options -- ./src/.libs/fuzz_target_x @@
```
