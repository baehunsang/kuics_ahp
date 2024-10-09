#익스코드 컴파일 후 fs에 넣고 cpio로 패킹
cd $(pwd)
if [ -e "ex.c" ]; then
	musl-gcc ./ex.c -o ./ex -static 
	cp ./ex ./fs/
fi
cd ./fs
find . -print0 | cpio -o --format=newc --null  > ../rootfs_updated.cpio
cd ../
