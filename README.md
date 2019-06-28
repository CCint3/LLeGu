# LLeGu

[![996.icu](https://img.shields.io/badge/link-996.icu-red.svg)](https://996.icu)  [![LICENSE](https://img.shields.io/badge/license-Anti%20996-blue.svg)](https://github.com/996icu/996.ICU/blob/master/LICENSE)

LLeGu 是一基于 "腾讯Legu" 的 Android ELF 加壳工具，所以起名为 "Like-LeGu LLeGu"。主要应用于*.so的加壳。

## 新特性

  - 没啥新特性：加入了一些加密算法，加密字符串，加密导入表等等。
  - 没啥新特性：更多的是希望你能自己编译它，使用它。然后看看它的效果。
  - 欢迎各位提出自己的意见和建议。

## 兼容性
  - 目前仅在Android-6.0.1_r77的系统上做了测试。

## 工程介绍
  - Extract: 加壳工具
    1. 初始化一些随机幻数，这些幻数应用于解密。
    2. 解析待加密的ELF，提取有用的信息。例如：段数量；段大小；导入表和字符串表。
    3. 使用zlib压缩每一个段，并使用TEA加密压缩后的数据。
       先压缩，再加密；那么解密时顺序是相反的，即先解密再解压；那么Cracker只需要Hook解压函数就可以DUMP我们的so；
       以后有时间的话，需要将加密和压缩顺序调换一下；防止Hook解压函数的DUMP；
    4. 生成settings.h，用于下一阶段的壳编译工作。其中记录了很多有用的信息。
    5. 生成ldscript，用于下一阶段的壳编译工作。GCC编译器识别该脚本，可以编译出特定的ELF文件。
    6. 执行run_make.bat去编译壳。
  - shell: 壳的主要代码
    1. 通过Extract.exe生成的settings.h和ldscript两个配置文件去编译壳。
    2. 壳代码基于 "腾讯LeGu"。

## 编译
  - 编辑run_make.bat，配置NDK的目录
  - Visual Studio 2017 将Extrace工程编译为 x86 Release
  - 将编译好的Extract.exe放入shell目录中
  - 命令行进入shell目录，并运行 Extract libxxx.so
  - 生成shell_bak.so即已经被加壳的so

## 效果图
![avatar](https://github.com/CCint3/LLeGu/blob/master/test.png?raw=true)
