# 베이스 이미지로 Ubuntu 22.04 사용
FROM ubuntu:22.04

# 필요한 패키지 업데이트 및 설치
RUN apt-get update && apt-get install -y \
    qemu-system-x86 \
    socat \
	wget \
	cpio \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# 현재 디렉터리의 파일들을 컨테이너로 복사
COPY rootfs.cpio /rootfs.cpio
COPY bzImage /bzImage
COPY main.sh /main.sh

# main.sh에 실행 권한 부여
RUN chmod +x /main.sh




