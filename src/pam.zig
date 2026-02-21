const std = @import("std");

pub const pam = @cImport({
    @cInclude("security/pam_appl.h");
});

pub const CredAction = enum(c_int) {
    establish = pam.PAM_ESTABLISH_CRED,
    delete = pam.PAM_DELETE_CRED,
    reinit = pam.PAM_REINITIALIZE_CRED,
    refresh = pam.PAM_REFRESH_CRED,
};

pub const CredFlags = struct {
    action: CredAction,
    silent: bool = false,
};

pub const AuthFlags = struct {
    silent: bool = false,
    disallow_null_authtok: bool = false,
};

pub const SessionFlags = struct {
    silent: bool = false,
};

fn authFlagsToInt(flags: AuthFlags) c_int {
    return (if (flags.silent) @as(c_int, @intCast(pam.PAM_SILENT)) else 0) |
        (if (flags.disallow_null_authtok) @as(c_int, @intCast(pam.PAM_DISALLOW_NULL_AUTHTOK)) else 0);
}

fn sessionFlagsToInt(flags: SessionFlags) c_int {
    return if (flags.silent) @as(c_int, @intCast(pam.PAM_SILENT)) else 0;
}

pub const Prompt = struct {
    message: []const u8,
    response: *pam.pam_response,
    allocator: std.mem.Allocator,

    pub fn respond(self: *const Prompt, value: []const u8) !void {
        if (self.response.resp) |existing| {
            const p = std.mem.span(existing);
            std.crypto.secureZero(u8, p);
            self.allocator.free(p);
        }
        self.response.resp = try self.allocator.dupeZ(u8, value);
        self.response.resp_retcode = 0;
    }
};

pub const Msg = union(enum) {
    prompt_echo_on: Prompt,
    prompt_echo_off: Prompt,
    text_info: []const u8,
    error_msg: []const u8,
};

pub const Messages = struct {
    raw: ?[*]?*const pam.pam_message,
    len: usize,
    responses: []pam.pam_response,
    allocator: std.mem.Allocator,

    pub const Iterator = struct {
        msgs: *const Messages,
        idx: usize = 0,

        pub fn next(self: *Iterator) !?Msg {
            if (self.idx >= self.msgs.len) return null;
            defer self.idx += 1;
            return try self.msgs.get(self.idx);
        }
    };

    pub fn get(self: *const Messages, idx: usize) !Msg {
        if (idx >= self.len) return error.IndexOutOfBounds;
        const raw_msgs = self.raw orelse return error.InvalidMessage;
        const raw_msg = raw_msgs[idx] orelse return error.InvalidMessage;
        const message = std.mem.span(raw_msg.msg);
        const prompt = Prompt{
            .message = message,
            .response = &self.responses[idx],
            .allocator = self.allocator,
        };
        return switch (raw_msg.msg_style) {
            pam.PAM_PROMPT_ECHO_ON => .{ .prompt_echo_on = prompt },
            pam.PAM_PROMPT_ECHO_OFF => .{ .prompt_echo_off = prompt },
            pam.PAM_TEXT_INFO => .{ .text_info = message },
            pam.PAM_ERROR_MSG => .{ .error_msg = message },
            else => error.UnknownMessageStyle,
        };
    }

    pub fn iter(self: *const Messages) Iterator {
        return .{ .msgs = self };
    }
};

const Responses = struct {
    responses: []pam.pam_response,
    allocator: std.mem.Allocator,

    fn init(allocator: std.mem.Allocator, count: usize) !Responses {
        if (count == 0) {
            return .{
                .responses = &[_]pam.pam_response{},
                .allocator = allocator,
            };
        }

        const responses = try allocator.alloc(pam.pam_response, count);
        @memset(responses, std.mem.zeroes(pam.pam_response));
        return .{
            .responses = responses,
            .allocator = allocator,
        };
    }

    fn deinit(self: *Responses) void {
        for (self.responses) |r| {
            if (r.resp) |r_resp| {
                const p = std.mem.span(r_resp);
                std.crypto.secureZero(u8, p);
                self.allocator.free(p);
            }
        }
        if (self.responses.len != 0) {
            self.allocator.free(self.responses);
        }
    }
};

pub fn Pam(comptime T: type) type {
    return struct {
        const Self = @This();

        pub const ConvFn = if (T == void)
            *const fn (
                allocator: std.mem.Allocator,
                msgs: Messages,
            ) anyerror!void
        else
            *const fn (
                allocator: std.mem.Allocator,
                msgs: Messages,
                ctx: *T,
            ) anyerror!void;

        pub const ConvState = if (T == void)
            struct {
                conv: ConvFn,

                var empty_state: ConvState = .{ .conv = emptyConv };

                /// Provides a conv which errors on prompt and ignores messages.
                pub fn discardAll() *ConvState {
                    return &empty_state;
                }

                fn emptyConv(_: std.mem.Allocator, msgs: Messages) !void {
                    var it = msgs.iter();
                    while (try it.next()) |msg| {
                        switch (msg) {
                            .prompt_echo_on, .prompt_echo_off => return error.PromptNotExpected,
                            else => {},
                        }
                    }
                }
            }
        else
            struct {
                ctx: *T,
                conv: ConvFn,
            };

        pub const Item = union(enum) {
            user: [:0]const u8,
            tty: [:0]const u8,
            rhost: [:0]const u8,
            ruser: [:0]const u8,
            user_prompt: [:0]const u8,
            authtok: [:0]const u8,
            oldauthtok: [:0]const u8,
            conv: *ConvState,
        };

        pub const Opts = struct {
            service_name: []const u8,
            state: *ConvState,
            user: ?[:0]const u8 = null,
        };

        handle: ?*pam.pam_handle,
        status: c_int = pam.PAM_SUCCESS,
        allocator: std.mem.Allocator,
        env_arena: std.heap.ArenaAllocator,
        session_open: bool = false,
        creds_established: bool = false,

        pub fn init(allocator: std.mem.Allocator, opts: Opts) PamError!Self {
            // pam copies this into the pam handle
            const conv_def = pam.pam_conv{
                .conv = convTrampoline,
                .appdata_ptr = opts.state,
            };

            var handle: ?*pam.pam_handle = undefined;
            const user_ptr = if (opts.user) |u| u.ptr else null;
            const status = pam.pam_start(opts.service_name.ptr, user_ptr, &conv_def, &handle);
            if (status != pam.PAM_SUCCESS) {
                return pamDiagnose(status);
            }

            return .{
                .handle = handle,
                .status = status,
                .allocator = allocator,
                .env_arena = std.heap.ArenaAllocator.init(allocator),
            };
        }


        pub fn deinit(self: *Self) void {
            if (self.handle == null) return;
            if (self.session_open) self.closeSession(.{ .silent = true }) catch {};
            if (self.creds_established) _ = pam.pam_setcred(self.handle, pam.PAM_DELETE_CRED);
            _ = pam.pam_end(self.handle, self.status);
            self.env_arena.deinit();
            self.handle = null;
        }

        pub fn authenticate(self: *Self, flags: AuthFlags) PamError!void {
            self.status = pam.pam_authenticate(self.handle, authFlagsToInt(flags));
            if (self.status != pam.PAM_SUCCESS) return pamDiagnose(self.status);
        }

        pub fn accountMgmt(self: *Self, flags: AuthFlags) PamError!void {
            self.status = pam.pam_acct_mgmt(self.handle, authFlagsToInt(flags));
            if (self.status != pam.PAM_SUCCESS) return pamDiagnose(self.status);
        }

        pub fn setCred(self: *Self, flags: CredFlags) PamError!void {
            const f = @intFromEnum(flags.action) |
                (if (flags.silent) @as(c_int, @intCast(pam.PAM_SILENT)) else 0);
            self.status = pam.pam_setcred(self.handle, f);
            if (self.status != pam.PAM_SUCCESS) return pamDiagnose(self.status);

            if (flags.action == .establish) {
                self.creds_established = true;
            } else if (flags.action == .delete) {
                self.creds_established = false;
            }
        }

        pub fn openSession(self: *Self, flags: SessionFlags) PamError!void {
            self.status = pam.pam_open_session(self.handle, sessionFlagsToInt(flags));
            if (self.status != pam.PAM_SUCCESS) return pamDiagnose(self.status);
            self.session_open = true;
        }

        pub fn closeSession(self: *Self, flags: SessionFlags) PamError!void {
            self.status = pam.pam_close_session(self.handle, sessionFlagsToInt(flags));
            if (self.status != pam.PAM_SUCCESS) return pamDiagnose(self.status);
            self.session_open = false;
        }

        pub fn setItem(self: *Self, item: Item) PamError!void {
            var conv_def: pam.pam_conv = undefined;
            const item_type: c_int = switch (item) {
                .user => pam.PAM_USER,
                .tty => pam.PAM_TTY,
                .rhost => pam.PAM_RHOST,
                .ruser => pam.PAM_RUSER,
                .user_prompt => pam.PAM_USER_PROMPT,
                .authtok => pam.PAM_AUTHTOK,
                .oldauthtok => pam.PAM_OLDAUTHTOK,
                .conv => blk: {
                    conv_def = pam.pam_conv{
                        .conv = convTrampoline,
                        .appdata_ptr = item.conv,
                    };
                    break :blk pam.PAM_CONV;
                },
            };
            const ptr: ?*const anyopaque = switch (item) {
                inline .user,
                .tty,
                .rhost,
                .ruser,
                .user_prompt,
                .authtok,
                .oldauthtok,
                => |s| @ptrCast(s.ptr),
                .conv => &conv_def,
            };
            self.status = pam.pam_set_item(self.handle, item_type, ptr);
            if (self.status != pam.PAM_SUCCESS) return pamDiagnose(self.status);
        }

        pub fn putEnv(self: *Self, kv: [:0]const u8) PamError!void {
            self.status = pam.pam_putenv(self.handle, kv);
            if (self.status != pam.PAM_SUCCESS) return pamDiagnose(self.status);
        }

        pub fn putEnvAlloc(self: *Self, key: []const u8, value: []const u8) !void {
            if (std.mem.indexOfScalar(u8, key, '=') != null) return error.InvalidPayload;
            const kv = try std.fmt.allocPrintSentinel(self.env_arena.allocator(), "{s}={s}", .{ key, value }, 0);
            try self.putEnv(kv);
        }

        pub fn addEnvListToMap(self: *Self, env_map: *std.process.EnvMap) !void {
            const env_list = self.getEnvList();
            defer freeEnvList(env_list);

            if (env_list) |list| {
                var i: usize = 0;
                while (list[i]) |entry| : (i += 1) {
                    const s = std.mem.span(entry);
                    const eq = std.mem.indexOfScalar(u8, s, '=') orelse continue;
                    if (eq == 0) continue;
                    try env_map.put(s[0..eq], s[eq + 1 ..]);
                }
            }
        }

        pub fn createEnvListMap(self: *Self) !std.process.EnvMap {
            var env_map = std.process.EnvMap.init(self.allocator);
            errdefer env_map.deinit();

            try self.addEnvListToMap(&env_map);

            return env_map;
        }

        fn getEnvList(self: *Self) ?[*:null]?[*:0]u8 {
            return pam.pam_getenvlist(self.handle);
        }

        fn freeEnvList(env_list: ?[*:null]?[*:0]u8) void {
            const list = env_list orelse return;
            var i: usize = 0;
            while (list[i]) |entry| : (i += 1) {
                std.c.free(@ptrCast(entry));
            }
            std.c.free(@ptrCast(list));
        }

        fn convTrampoline(
            num_msg: c_int,
            msg: ?[*]?*const pam.pam_message,
            resp: ?*?[*]pam.pam_response,
            appdata_ptr: ?*anyopaque,
        ) callconv(.c) c_int {
            const state_ptr = appdata_ptr orelse return pam.PAM_CONV_ERR;
            const state: *ConvState = @ptrCast(@alignCast(state_ptr));
            if (num_msg < 0) return pam.PAM_CONV_ERR;

            const count: usize = @intCast(num_msg);
            const allocator = std.heap.c_allocator;
            var responses = Responses.init(allocator, count) catch return pam.PAM_BUF_ERR;

            const messages = Messages{
                .raw = msg,
                .len = count,
                .responses = responses.responses,
                .allocator = allocator,
            };

            if (T == void) {
                state.conv(allocator, messages) catch |err| {
                    responses.deinit();
                    return convErrorToPam(err);
                };
            } else {
                state.conv(allocator, messages, state.ctx) catch |err| {
                    responses.deinit();
                    return convErrorToPam(err);
                };
            }

            if (resp) |out| {
                out.* = if (count == 0) null else responses.responses.ptr;
                return pam.PAM_SUCCESS;
            }

            responses.deinit();
            return pam.PAM_CONV_ERR;
        }

        fn convErrorToPam(err: anyerror) c_int {
            return switch (err) {
                error.OutOfMemory => pam.PAM_BUF_ERR,
                error.Abort => pam.PAM_ABORT,
                else => pam.PAM_CONV_ERR,
            };
        }
    };
}

pub const PamError = error{
    AccountExpired,
    AuthError,
    AuthInfoUnavailable,
    BufferError,
    CredentialsError,
    CredentialsExpired,
    CredentialsInsufficient,
    CredentialsUnavailable,
    MaximumTries,
    NewAuthTokenRequired,
    PermissionDenied,
    SessionError,
    SystemError,
    UserUnknown,
    Abort,
    Unknown,
};

fn pamDiagnose(status: c_int) PamError {
    return switch (status) {
        pam.PAM_SUCCESS => unreachable,
        pam.PAM_ACCT_EXPIRED => error.AccountExpired,
        pam.PAM_AUTH_ERR => error.AuthError,
        pam.PAM_AUTHINFO_UNAVAIL => error.AuthInfoUnavailable,
        pam.PAM_BUF_ERR => error.BufferError,
        pam.PAM_CRED_ERR => error.CredentialsError,
        pam.PAM_CRED_EXPIRED => error.CredentialsExpired,
        pam.PAM_CRED_INSUFFICIENT => error.CredentialsInsufficient,
        pam.PAM_CRED_UNAVAIL => error.CredentialsUnavailable,
        pam.PAM_MAXTRIES => error.MaximumTries,
        pam.PAM_NEW_AUTHTOK_REQD => error.NewAuthTokenRequired,
        pam.PAM_PERM_DENIED => error.PermissionDenied,
        pam.PAM_SESSION_ERR => error.SessionError,
        pam.PAM_SYSTEM_ERR => error.SystemError,
        pam.PAM_USER_UNKNOWN => error.UserUnknown,
        pam.PAM_ABORT => error.Abort,
        else => error.Unknown,
    };
}
