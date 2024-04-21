FROM fedora:41

RUN dnf update -y

RUN dnf install -y clang clang-tools-extra meson wget llvm git unzip cmake zsh \
    cppcheck curl openssl-devel

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain nightly

RUN chsh -s /usr/bin/zsh

RUN sh -c "$(wget -O- https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --keep-zshrc
