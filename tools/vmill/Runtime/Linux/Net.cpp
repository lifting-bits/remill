/* Copyright 2017 Peter Goodman (peter@trailofbits.com), all rights reserved. */

namespace {

static Memory *SysSocket(Memory *memory, State *state,
                         const SystemCallABI &syscall) {
  int domain = 0;
  int type = 0;
  int protocol = 0;
  if (!syscall.TryGetArgs(memory, state, &domain, &type, &protocol)) {
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  auto fd = socket(domain, type, protocol);
  if (-1 == fd) {
    return syscall.SetReturn(memory, state, -errno);
  } else {
    return syscall.SetReturn(memory, state, fd);
  }
}

static Memory *SysBind(Memory *memory, State *state,
                       const SystemCallABI &syscall) {
  int sockfd = -1;
  addr_t addr = 0;
  socklen_t addrlen = 0;
  if (!syscall.TryGetArgs(memory, state, &sockfd, &addr, &addrlen)) {
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  struct sockaddr addr_val = {};
  if (addr) {
    if (!TryReadMemory(memory, addr, &addr_val)) {
      return syscall.SetReturn(memory, state, -EFAULT);
    }
  }

  auto ret = bind(sockfd, (addr ? &addr_val : nullptr), addrlen);
  if (-1 == ret) {
    return syscall.SetReturn(memory, state, -errno);
  } else {
    return syscall.SetReturn(memory, state, ret);
  }
}

static Memory *SysConnect(Memory *memory, State *state,
                          const SystemCallABI &syscall) {
  int sockfd = -1;
  addr_t addr = 0;
  socklen_t addrlen = 0;
  if (!syscall.TryGetArgs(memory, state, &sockfd, &addr, &addrlen)) {
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  struct sockaddr addr_val = {};
  if (addr) {
    if (!TryReadMemory(memory, addr, &addr_val)) {
      return syscall.SetReturn(memory, state, -EFAULT);
    }
  }

  auto ret = connect(sockfd, (addr ? &addr_val : nullptr), addrlen);
  if (-1 == ret) {
    return syscall.SetReturn(memory, state, -errno);
  } else {
    return syscall.SetReturn(memory, state, ret);
  }
}

static Memory *SysListen(Memory *memory, State *state,
                         const SystemCallABI &syscall) {
  int sockfd = -1;
  int backlog = 0;
  if (!syscall.TryGetArgs(memory, state, &sockfd, &backlog)) {
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  auto ret = listen(sockfd, backlog);
  if (-1 == ret) {
    return syscall.SetReturn(memory, state, -errno);
  } else {
    return syscall.SetReturn(memory, state, ret);
  }
}

struct SockAddress : public sockaddr {
  uint8_t extra_space[1024 - sizeof(struct sockaddr)];
};

static SockAddress gSockAddrBuf = {};

static Memory *DoSysAccept(Memory *memory, State *state,
                           const SystemCallABI &syscall,
                           int fd, addr_t addr, addr_t addr_len,
                           int flags) {
  socklen_t addr_len_val = 0;

  if (addr) {
    if (!TryReadMemory(memory, addr_len, &addr_len_val)) {
      return syscall.SetReturn(memory, state, -EFAULT);
    }

    assert(addr_len_val <= sizeof(SockAddress));

    if (!CanReadMemory(memory, addr, addr_len_val) ||
        !CanWriteMemory(memory, addr, addr_len_val)) {
      return syscall.SetReturn(memory, state, -EFAULT);
    }

    CopyFromMemory(memory, &gSockAddrBuf, addr, addr_len_val);
  }

  auto ret_fd = accept4(
      fd, (addr ? &gSockAddrBuf : nullptr),
      (addr_len ? &addr_len_val : nullptr), flags);

  if (-1 == ret_fd) {
    return syscall.SetReturn(memory, state, -errno);
  }

  if (addr && addr_len) {
    memory = CopyToMemory(memory, addr, &gSockAddrBuf, addr_len_val);

    if (!TryWriteMemory(memory, addr_len, addr_len_val)) {
      return syscall.SetReturn(memory, state, -EFAULT);
    }
  }

  return syscall.SetReturn(memory, state, ret_fd);
}

static Memory *SysAccept(Memory *memory, State *state,
                         const SystemCallABI &syscall) {
  int fd = -1;
  addr_t addr = 0;
  addr_t addr_len = 0;
  if (!syscall.TryGetArgs(memory, state, &fd, &addr, &addr_len)) {
    return syscall.SetReturn(memory, state, -EFAULT);
  }
  return DoSysAccept(memory, state, syscall, fd, addr, addr_len, 0);
}

static Memory *SysAccept4(Memory *memory, State *state,
                         const SystemCallABI &syscall) {
  int fd = -1;
  addr_t addr = 0;
  addr_t addr_len = 0;
  int flags = 0;
  if (!syscall.TryGetArgs(memory, state, &fd, &addr, &addr_len, &flags)) {
    return syscall.SetReturn(memory, state, -EFAULT);
  }
  return DoSysAccept(memory, state, syscall, fd, addr, addr_len, flags);
}

static Memory *SysGetSockName(Memory *memory, State *state,
                              const SystemCallABI &syscall) {
  int fd = -1;
  addr_t addr = 0;
  addr_t len = 0;
  if (!syscall.TryGetArgs(memory, state, &fd, &addr, &len)) {
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  socklen_t len_val = 0;
  if (!TryReadMemory(memory, len, &len_val)) {
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  assert(len_val <= sizeof(SockAddress));

  if (!CanReadMemory(memory, addr, len_val) ||
      !CanWriteMemory(memory, addr, len_val)) {
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  CopyFromMemory(memory, &gSockAddrBuf, addr, len_val);

  if (!getsockname(fd, &gSockAddrBuf, &len_val)) {
    CopyToMemory(memory, addr, &gSockAddrBuf, len_val);
    if (!TryWriteMemory(memory, len, &len_val)) {
      return syscall.SetReturn(memory, state, -EFAULT);
    } else {
      return syscall.SetReturn(memory, state, 0);
    }
  } else {
    return syscall.SetReturn(memory, state, -errno);
  }
}

static Memory *SysGetPeerName(Memory *memory, State *state,
                              const SystemCallABI &syscall) {
  int fd = -1;
  addr_t addr = 0;
  addr_t len = 0;
  if (!syscall.TryGetArgs(memory, state, &fd, &addr, &len)) {
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  socklen_t len_val = 0;
  if (!TryReadMemory(memory, len, &len_val)) {
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  assert(len_val <= sizeof(SockAddress));

  if (!CanReadMemory(memory, addr, len_val) ||
      !CanWriteMemory(memory, addr, len_val)) {
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  CopyFromMemory(memory, &gSockAddrBuf, addr, len_val);

  if (!getpeername(fd, &gSockAddrBuf, &len_val)) {
    CopyToMemory(memory, addr, &gSockAddrBuf, len_val);
    if (!TryWriteMemory(memory, len, &len_val)) {
      return syscall.SetReturn(memory, state, -EFAULT);
    } else {
      return syscall.SetReturn(memory, state, 0);
    }
  } else {
    return syscall.SetReturn(memory, state, -errno);
  }
}

struct SocketVector {
  int pair[2];
} __attribute__((packed));

static Memory *SysSocketPair(Memory *memory, State *state,
                             const SystemCallABI &syscall) {
  int domain = 0;
  int type = 0;
  int protocol = 0;
  addr_t socket_vector = 0;
  if (!syscall.TryGetArgs(memory, state, &domain, &type,
                          &protocol, &socket_vector)) {
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  SocketVector vec = {};
  if (!TryReadMemory(memory, socket_vector, &vec)) {
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  if (!socketpair(domain, type, protocol, vec.pair)) {
    if (!TryWriteMemory(memory, socket_vector, vec)) {
      return syscall.SetReturn(memory, state, -EFAULT);
    } else {
      return syscall.SetReturn(memory, state, 0);
    }
  } else {
    return syscall.SetReturn(memory, state, -errno);
  }
}

static Memory *DoSysSendTo(Memory *memory, State *state,
                           const SystemCallABI &syscall,
                           int fd, addr_t buf, size_t n, int flags,
                           addr_t addr, socklen_t addr_len) {
  assert(addr_len <= sizeof(SockAddress));

  if (!n) {
    return syscall.SetReturn(memory, state, -EINVAL);
  }

  if (addr) {
    if (!CanReadMemory(memory, addr, addr_len)) {
      return syscall.SetReturn(memory, state, -EFAULT);
    }
    CopyFromMemory(memory, &gSockAddrBuf, addr, addr_len);
  }

  if (!CanReadMemory(memory, buf, n)) {
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  auto buf_val = new uint8_t[n];
  CopyFromMemory(memory, buf_val, buf, n);

  auto ret = sendto(
      fd, buf_val, n, flags, (addr ? &gSockAddrBuf : nullptr), addr_len);
  auto err = errno;
  delete[] buf_val;
  if (-1 == ret) {
    return syscall.SetReturn(memory, state, -err);
  } else {
    return syscall.SetReturn(memory, state, ret);
  }
}

static Memory *SysSend(Memory *memory, State *state,
                       const SystemCallABI &syscall) {
  int fd = -1;
  addr_t buf = 0;
  size_t n = 0;
  int flags = 0;
  if (!syscall.TryGetArgs(memory, state, &fd, &buf, &n, &flags)) {
    return syscall.SetReturn(memory, state, -EFAULT);
  }
  return DoSysSendTo(memory, state, syscall, fd, buf, n, flags, 0, 0);
}

static Memory *SysSendTo(Memory *memory, State *state,
                         const SystemCallABI &syscall) {
  int fd = -1;
  addr_t buf = 0;
  size_t n = 0;
  int flags = 0;
  addr_t addr = 0;
  socklen_t addr_len = 0;
  if (!syscall.TryGetArgs(memory, state, &fd, &buf, &n, &flags,
                          &addr, &addr_len)) {
    return syscall.SetReturn(memory, state, -EFAULT);
  }
  return DoSysSendTo(memory, state, syscall, fd, buf, n, flags, addr, addr_len);
}

static Memory *DoSysRecvFrom(Memory *memory, State *state,
                             const SystemCallABI &syscall,
                             int fd, addr_t buf, size_t n, unsigned flags,
                             addr_t addr, addr_t addr_len) {
  assert(addr_len <= sizeof(SockAddress));

  if (!n) {
    return syscall.SetReturn(memory, state, -EINVAL);
  }

  socklen_t addr_len_val = 0;
  if (addr) {
    if (!TryReadMemory(memory, addr_len, &addr_len_val) ||
        !CanReadMemory(memory, addr, addr_len)) {
      return syscall.SetReturn(memory, state, -EFAULT);
    }
    CopyFromMemory(memory, &gSockAddrBuf, addr, addr_len);
  }

  if (!CanReadMemory(memory, buf, n)) {
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  auto buf_val = new uint8_t[n];

  CopyFromMemory(memory, buf_val, buf, n);

  auto ret = recvfrom(
      fd, buf_val, n, static_cast<int>(flags),
      (addr ? &gSockAddrBuf : nullptr),
      (addr_len ? &addr_len_val : nullptr));
  auto err = errno;

  if (!CanWriteMemory(memory, addr, addr_len)) {
    delete[] buf_val;
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  CopyToMemory(memory, buf, buf_val, n);
  delete[] buf_val;

  if (addr) {
    if (!CopyToMemory(memory, addr, &gSockAddrBuf, addr_len_val) ||
        !TryWriteMemory(memory, addr_len, addr_len_val)) {
      return syscall.SetReturn(memory, state, -EFAULT);
    }
  }

  if (-1 == ret) {
    return syscall.SetReturn(memory, state, -err);
  } else {
    return syscall.SetReturn(memory, state, ret);
  }
}

static Memory *SysRecv(Memory *memory, State *state,
                       const SystemCallABI &syscall) {
  int fd = -1;
  addr_t buf = 0;
  size_t n = 0;
  unsigned flags = 0;
  if (!syscall.TryGetArgs(memory, state, &fd, &buf, &n, &flags)) {
    return syscall.SetReturn(memory, state, -EFAULT);
  }
  return DoSysRecvFrom(memory, state, syscall, fd, buf, n, flags, 0, 0);
}

static Memory *SysRecvFrom(Memory *memory, State *state,
                           const SystemCallABI &syscall) {
  int fd = -1;
  addr_t buf = 0;
  size_t n = 0;
  unsigned flags = 0;
  addr_t addr = 0;
  addr_t addr_len = 0;
  if (!syscall.TryGetArgs(memory, state, &fd, &buf, &n, &flags,
                          &addr, &addr_len)) {
    return syscall.SetReturn(memory, state, -EFAULT);
  }
  return DoSysRecvFrom(memory, state, syscall, fd, buf, n,
                       flags, addr, addr_len);
}

static Memory *SysShutdown(Memory *memory, State *state,
                           const SystemCallABI &syscall) {
  int socket = -1;
  int how = 0;
  if (!syscall.TryGetArgs(memory, state, &socket, &how)) {
    return syscall.SetReturn(memory, state, -EFAULT);
  }
  if (!shutdown(socket, how)) {
    return syscall.SetReturn(memory, state, 0);
  } else {
    return syscall.SetReturn(memory, state, -errno);
  }
}

// TODO(pag): Not clear how to make a compatibility version of this.
static Memory *SysSetSockOpt(Memory *memory, State *state,
                             const SystemCallABI &syscall) {
  int socket = -1;
  int level = 0;
  int option_name = 0;
  addr_t option_value = 0;
  socklen_t option_len = 0;
  if (!syscall.TryGetArgs(memory, state, &socket, &level, &option_name,
                          &option_value, &option_len)) {
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  if (!option_len) {
    return syscall.SetReturn(memory, state, -EINVAL);
  } else if (!CanReadMemory(memory, option_value, option_len)) {
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  auto option_value_data = new uint8_t[option_len];
  CopyFromMemory(memory, option_value_data, option_value, option_len);

  auto ret = setsockopt(socket, level, option_name,
                        option_value_data, option_len);

  auto err = errno;
  delete[] option_value_data;

  if (-1 == ret) {
    return syscall.SetReturn(memory, state, -err);
  } else {
    return syscall.SetReturn(memory, state, 0);
  }
}

// TODO(pag): Not clear how to make a compatibility version of this.
static Memory *SysGetSockOpt(Memory *memory, State *state,
                             const SystemCallABI &syscall) {
  int socket = -1;
  int level = 0;
  int option_name = 0;
  addr_t option_value = 0;
  addr_t option_len = 0;
  if (!syscall.TryGetArgs(memory, state, &socket, &level, &option_name,
                          &option_value, &option_len)) {
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  socklen_t option_len_val = 0;
  if (!TryReadMemory(memory, option_len, &option_len_val) ||
      !CanReadMemory(memory, option_value, option_len_val)) {
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  if (!option_len_val) {
    return syscall.SetReturn(memory, state, -EINVAL);
  }

  auto option_value_data = new uint8_t[option_len_val];
  CopyFromMemory(memory, option_value_data, option_value, option_len_val);

  auto ret = getsockopt(socket, level, option_name,
                        option_value_data, &option_len_val);

  if (-1 == ret) {
    auto err = errno;
    delete[] option_value_data;
    return syscall.SetReturn(memory, state, -err);
  }

  if (!CanWriteMemory(memory, option_value, option_len_val) ||
      !TryWriteMemory(memory, option_len, &option_len_val)) {
    delete[] option_value_data;
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  CopyToMemory(memory, option_value, option_value_data, option_len_val);
  delete[] option_value_data;

  return syscall.SetReturn(memory, state, 0);
}

template <typename IOVecT>
struct IOVec final : public iovec {
  IOVec(void) {
    iov_base = nullptr;
    iov_len = 0;
  }

  int Import(Memory *&memory, IOVecT &compat) {
    if (!compat.iov_base) {
      compat.iov_len = 0;
    }

    if (0 > compat.iov_len) {
      return EINVAL;
    }

    if (!CanReadMemory(memory, compat.iov_base, compat.iov_len)) {
      return EFAULT;
    }

    iov_len = compat.iov_len;
    iov_base = new uint8_t[iov_len];
    CopyFromMemory(memory, iov_base, compat.iov_base, iov_len);
    return 0;
  }

  int Export(Memory *&memory, IOVecT &compat) {
    if (iov_len) {
      if (!CanWriteMemory(memory, compat.iov_base, iov_len)) {
        return EFAULT;
      }
      CopyToMemory(memory, compat.iov_base, iov_base, iov_len);
    }
    compat.iov_len = static_cast<decltype(compat.iov_len)>(iov_len);
    return 0;
  }

  ~IOVec(void) {
    if (iov_base) {
      delete[] reinterpret_cast<uint8_t *>(iov_base);
    }
  }
};

template <typename MsgHdrT, typename IOVecT>
struct MessageHeader final : public msghdr {

  MessageHeader(void)
      : orig_iov(nullptr) {
    msg_name = nullptr;
    msg_namelen = 0;
    msg_iov = nullptr;
    msg_iovlen = 0;
    msg_control = nullptr;
    msg_controllen = 0;
    msg_flags = 0;
  }

  int Import(Memory *&memory, MsgHdrT &compat) {
    if (!compat.msg_name) {
      compat.msg_namelen = 0;
    }
    if (!compat.msg_iov) {
      compat.msg_iovlen = 0;
    }
    if (!compat.msg_control) {
      compat.msg_controllen = 0;
    }

    if (0 > compat.msg_namelen || 0 > compat.msg_iovlen ||
        0 > compat.msg_controllen) {
      return EINVAL;
    }

    if (compat.msg_namelen) {
      if (!CanReadMemory(memory, compat.msg_name, compat.msg_namelen)) {
        return EFAULT;
      }

      // Import the message name.
      msg_namelen = compat.msg_namelen;
      msg_name = new uint8_t[msg_namelen];
      CopyFromMemory(memory, msg_name, compat.msg_name, msg_namelen);
    }

    if (compat.msg_iovlen) {
      auto total_len = compat.msg_iovlen * sizeof(IOVecT);
      if (!CanReadMemory(memory, compat.msg_iov, total_len)) {
        return EFAULT;
      }

      msg_iovlen = compat.msg_iovlen;
      orig_iov = new IOVecT[msg_iovlen];
      CopyFromMemory(memory, orig_iov, compat.msg_iov, total_len);

      auto iov = new IOVec<IOVecT>[msg_iovlen];
      msg_iov = iov;

      // Import each io vector and their associated data.
      for (auto i = 0U; i < msg_iovlen; ++i) {
        if (auto ret = iov[i].Import(memory, orig_iov[i])) {
          return ret;
        }
      }
    }

    if (compat.msg_control) {
      if (!CanReadMemory(memory, compat.msg_control, compat.msg_controllen)) {
        return EFAULT;
      }

      msg_controllen = compat.msg_controllen;
      msg_control = new uint8_t[msg_controllen];
      CopyFromMemory(memory, msg_control, compat.msg_control, msg_controllen);
    }

    return 0;
  }

  int Export(Memory *&memory, MsgHdrT &compat) {
    if (msg_name) {
      if (!CanWriteMemory(memory, compat.msg_name, msg_namelen)) {
        return EFAULT;
      }
      CopyToMemory(memory, compat.msg_name, msg_name, msg_namelen);
    }

    if (msg_iov) {
      auto iov = reinterpret_cast<IOVec<IOVecT> *>(msg_iov);
      for (auto i = 0U; i < msg_iovlen; ++i) {
        if (auto ret = iov[i].Export(memory, orig_iov[i])) {
          return ret;
        }
      }
      if (!CanWriteMemory(memory, compat.msg_iov, msg_iovlen)) {
        return -EFAULT;
      }

      auto total_len = msg_iovlen * sizeof(IOVecT);
      CopyToMemory(memory, compat.msg_iov, orig_iov, total_len);
    }

    if (msg_control) {
      if (!CanWriteMemory(memory, compat.msg_control, msg_controllen)) {
        return EFAULT;
      }
      CopyToMemory(memory, compat.msg_control, msg_control, msg_controllen);
    }

    compat.msg_flags = msg_flags;
    compat.msg_namelen = msg_namelen;
    compat.msg_iovlen = static_cast<decltype(compat.msg_iovlen)>(msg_iovlen);
    compat.msg_controllen = static_cast<decltype(compat.msg_controllen)>(
        msg_controllen);
    return 0;
  }

  ~MessageHeader(void) {
    if (msg_name) {
      delete[] reinterpret_cast<uint8_t *>(msg_name);
    }
    if (msg_iov) {
      delete[] reinterpret_cast<IOVec<IOVecT> *>(msg_iov);
    }
    if (orig_iov) {
      delete[] orig_iov;
    }
    if (msg_control) {
      delete[] reinterpret_cast<uint8_t *>(msg_control);
    }
  }

  IOVecT *orig_iov;
};

template <typename MsgHdrT, typename IOVecT>
static Memory *SysSendMsg(Memory *memory, State *state,
                          const SystemCallABI &syscall) {
  int socket = -1;
  addr_t message = 0;
  int flags = 0;
  if (!syscall.TryGetArgs(memory, state, &socket, &message, &flags)) {
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  MsgHdrT compat_header = {};
  if (!TryReadMemory(memory, message, &compat_header)) {
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  MessageHeader<MsgHdrT, IOVecT> header;
  auto err = header.Import(memory, compat_header);
  if (err) {
    return syscall.SetReturn(memory, state, -err);
  }

  auto ret = sendmsg(socket, &header, flags);
  if (-1 == ret) {
    return syscall.SetReturn(memory, state, -errno);
  } else {
    return syscall.SetReturn(memory, state, ret);
  }
}

template <typename MsgHdrT, typename IOVecT>
static Memory *SysRecvMsg(Memory *memory, State *state,
                          const SystemCallABI &syscall) {
  int socket = -1;
  addr_t message = 0;
  int flags = 0;
  if (!syscall.TryGetArgs(memory, state, &socket, &message, &flags)) {
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  MsgHdrT compat_header = {};
  if (!TryReadMemory(memory, message, &compat_header)) {
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  MessageHeader<MsgHdrT, IOVecT> header;
  auto err = header.Import(memory, compat_header);
  if (err) {
    return syscall.SetReturn(memory, state, -err);
  }

  auto ret = recvmsg(socket, &header, flags);
  if (-1 == ret) {
    return syscall.SetReturn(memory, state, -errno);
  }

  err = header.Export(memory, compat_header);
  if (!TryWriteMemory(memory, message, compat_header)) {
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  return syscall.SetReturn(memory, state, ret);
}

#if 0

// TODO(pag): Eventually, to handle these we need to remove the `orig_iov`
//            from inside of the `MessageHeader` type.
template <typename MsgHdrT, typename IOVecT>
struct MultiMessageHeader {
  struct CompatType {
    MsgHdrT msg_hdr;
    unsigned msg_len;
  };

  MultiMessageHeader(void)
      : msg_hdr(),
        msg_len(0) {}

  int Import(Memory *&memory, CompatType &compat) {
    msg_len = compat.msg_len;
    return msg_hdr.Import(memory, compat.msg_hdr);
  }

  int Export(Memory *&memory, CompatType &compat) {
    compat.msg_len = msg_len;
    return msg_hdr.Export(memory, compat.msg_hdr);
  }

  MessageHeader<MsgHdrT, IOVecT> msg_hdr;
  unsigned msg_len;
};


extern "C" {

// Forward declarations, just in case we're compiling on a non-Linux OS
struct mmsghdr;

extern int sendmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen,
                    unsigned int flags);

extern int recvmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen,
                    unsigned int flags, struct timespec *timeout);
}  // extern C

template <typename MsgHdrT, typename IOVecT, typename TimeSpecT>
static Memory *SysRecvMmsg(Memory *memory, State *state,
                           const SystemCallABI &syscall) {
  using MmsgHdrT = typename MultiMessageHeader<MsgHdrT, IOVecT>::CompatType;

  int socket = -1;
  addr_t msgvec = 0;
  unsigned vlen = 0;
  unsigned flags = 0;
  addr_t timeout = 0;
  if (!syscall.TryGetArgs(memory, state, &socket, &msgvec, &vlen, &flags,
                          &timeout)) {
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  auto total_size = sizeof(MmsgHdrT) * vlen;
  if (!CanReadMemory(memory, msgvec, total_size)) {
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  auto compat_vec = new MmsgHdrT[vlen];
  auto vec = new MultiMessageHeader<MsgHdrT, IOVecT>[vlen];

  delete[] vec;
  delete[] compat_vec;

  MmsgHdrT compat_header = {};
  if (!TryReadMemory(memory, message, &compat_header)) {
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  MessageHeader<MsgHdrT, IOVecT> header;
  auto err = header.Import(memory, compat_header);
  if (err) {
    return syscall.SetReturn(memory, state, -err);
  }

  auto ret = recvmsg(socket, &header, flags);
  if (-1 == ret) {
    return syscall.SetReturn(memory, state, -errno);
  }

  err = header.Export(memory, compat_header);
  if (!TryWriteMemory(memory, message, compat_header)) {
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  return syscall.SetReturn(memory, state, ret);
}

#endif

// ABI for argument pack passed to the `socketcall` system call. This is
// parameterized by `AddrT` because if this is a 32-bit compatibility
// `socketcall` then all addresses and arguments must be treated as 32-bit
// values.
template <typename AddrT>
class SocketCallABI : public SystemCallABI {
 public:
  explicit SocketCallABI(addr_t arg_addr_)
      : arg_addr(arg_addr_) {}

  virtual ~SocketCallABI(void) = default;

  addr_t GetReturnAddress(Memory *, addr_t ret_addr) const override {
    return ret_addr;
  }

  addr_t GetSystemCallNum(Memory *, State *state) const override {
    return state->gpr.rax.aword;
  }

  Memory *SetReturn(Memory *memory, State *state,
                    addr_t ret_val) const override {
    state->gpr.rax.aword = static_cast<AddrT>(ret_val);
    return memory;
  }

  bool CanReadArgs(Memory *memory, State *, int num_args) const override {
    return CanReadMemory(
        memory, arg_addr, static_cast<size_t>(num_args) * sizeof(AddrT));
  }

  addr_t GetArg(Memory *&memory, State *state, int i) const override {
    return ReadMemory<AddrT>(
        memory,
        arg_addr + static_cast<addr_t>(static_cast<addr_t>(i) * sizeof(AddrT)));
  }

  addr_t arg_addr;
};

template <typename AddrT>
static Memory *SysSocketCall(Memory *memory, State *state,
                             const SystemCallABI &syscall) {
  int call = 0;
  AddrT args = 0;
  if (!syscall.TryGetArgs(memory, state, &call, &args)) {
    return syscall.SetReturn(memory, state, -EFAULT);
  }

  if (0 > call || call > SYS_SENDMMSG) {
    return syscall.SetReturn(memory, state, -EINVAL);
  }

  SocketCallABI<AddrT> abi(args);
  switch (call) {
    case SYS_SOCKET:
      return SysSocket(memory, state, abi);
    case SYS_BIND:
      return SysBind(memory, state, abi);
    case SYS_CONNECT:
      return SysConnect(memory, state, abi);
    case SYS_LISTEN:
      return SysListen(memory, state, abi);
    case SYS_ACCEPT:
      return SysAccept(memory, state, abi);
    case SYS_GETSOCKNAME:
      return SysGetSockName(memory, state, abi);
    case SYS_GETPEERNAME:
      return SysGetPeerName(memory, state, abi);
    case SYS_SOCKETPAIR:
      return SysSocketPair(memory, state, abi);
    case SYS_SEND:
      return SysSend(memory, state, abi);
    case SYS_RECV:
      return SysRecv(memory, state, abi);
    case SYS_SENDTO:
      return SysSendTo(memory, state, abi);
    case SYS_RECVFROM:
      return SysRecvFrom(memory, state, abi);
    case SYS_SHUTDOWN:
      return SysShutdown(memory, state, abi);
    case SYS_SETSOCKOPT:
      return SysSetSockOpt(memory, state, abi);
    case SYS_GETSOCKOPT:
      return SysGetSockOpt(memory, state, abi);
    case SYS_SENDMSG:
      return SysSendMsg<linux32_msghdr, linux32_iovec>(memory, state, abi);
    case SYS_RECVMSG:
      return SysRecvMsg<linux32_msghdr, linux32_iovec>(memory, state, abi);
    case SYS_ACCEPT4:
      return SysAccept4(memory, state, abi);

    case SYS_RECVMMSG:
    case SYS_SENDMMSG:
    default:
      return abi.SetReturn(
          memory, state,
          static_cast<addr_t>(static_cast<addr_diff_t>(-ENOSYS)));
  }
}

}  // namespace
