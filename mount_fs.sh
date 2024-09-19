cd $(pwd)
mkdir fs 
cd fs
 cpio -idv <../rootfs.cpio #마운트
 #그 다음부터는 rootfs_updated.cpio로 수정할 것
 cd ../

