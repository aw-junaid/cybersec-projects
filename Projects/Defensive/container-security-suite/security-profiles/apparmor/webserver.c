#include <tunables/global>

profile webserver /usr/sbin/nginx flags=(attach_disconnected) {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  
  capability net_bind_service,
  capability setgid,
  capability setuid,
  
  network inet tcp,
  network inet udp,
  network inet6 tcp,
  network inet6 udp,
  
  /etc/nginx/** r,
  /var/lib/nginx/** rw,
  /var/log/nginx/** w,
  /run/nginx.pid w,
  
  deny /etc/passwd rwxl,
  deny /bin/** x,
  deny /usr/bin/** x,
  
  deny @{PROC}/sys/kernel/** r,
}
