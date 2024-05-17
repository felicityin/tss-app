# Install

https://studygolang.com/articles/19679
https://www.cnblogs.com/ghj1976/p/gomobile-pei-zhi-peng-dao-de-wen-ti-ji-lu.html
https://githubwyb.github.io/blogs/2022-05-24-gomobile/

https://stackoverflow.com/questions/44432356/how-do-i-install-xcode-on-my-ubuntu-machine
https://stackoverflow.com/questions/48674104/clang-error-while-loading-shared-libraries-libtinfo-so-5-cannot-open-shared-o

# Build

```
cd eddsacmp/keygen
# cd eddsacmp/onsign

gomobile init

# 27 is version
# ls Android/Sdk/ndk/
# 27.0.11718014
gomobile bind -androidapi 27 -target=android .

# gomobile bind -target=ios .
```
