FROM debian:latest

#
# GitHub labels
#

LABEL com.github.actions.name="TULIPS builder" \
      com.github.actions.description="Build and test the TULIPS project" \
      com.github.actions.icon="check-circle" \
      com.github.actions.color="blue"

#
# Generic labels
#

LABEL repository="https://github.com/xenogenics/tulips-builder.git" \
      maintainer="Xavier R. Guérin <xguerin@users.noreply.github.com>"

#
# Set the APT frontend
#

ENV DEBIAN_FRONTEND=noninteractive

#
# Install the CA certificates
#

RUN apt update && apt upgrade -y
RUN apt install -y wget

#
# Add the official LLVM repository
#

RUN wget -O /etc/apt/trusted.gpg.d/llvm.asc https://apt.llvm.org/llvm-snapshot.gpg.key 
RUN echo "deb http://apt.llvm.org/bookworm/ llvm-toolchain-bookworm-15 main" > /etc/apt/sources.list.d/llvm.list

#
# Update the database
#

RUN apt update && apt upgrade -y

#
# Install the build tools
#

RUN apt install -y    \
      clang-15        \
      clang-format-15 \
      clang-tidy-15   \
      cmake           \
      make            \
      ninja-build     \
      libgtest-dev    \
      libpcap-dev     \
      libtclap-dev    \
      libssl-dev

#
# Links
#

RUN ln -s /usr/bin/clang-15 /usr/bin/clang \
 && ln -s /usr/bin/clang++-15 /usr/bin/clang++ \
 && ln -s /usr/bin/clang-format-15 /usr/bin/clang-format \
 && ln -s /usr/bin/clang-tidy-15 /usr/bin/clang-tidy