const std = @import("std");
const pam = @import("pam");

const AppState = struct {
    termios: std.posix.termios,
    io: std.Io,
};

fn conv(allocator: std.mem.Allocator, msgs: pam.Messages, ctx: *AppState) anyerror!void {
    _ = allocator;
    var stdout_buf: [1024]u8 = undefined;
    var stderr_buf: [1024]u8 = undefined;
    var stdin_buf: [1024]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(ctx.io, &stdout_buf);
    var stderr_writer = std.Io.File.stderr().writer(ctx.io, &stderr_buf);
    var stdin_reader = std.Io.File.stdin().reader(ctx.io, &stdin_buf);
    const stdout = &stdout_writer.interface;
    const stderr = &stderr_writer.interface;
    const stdin = &stdin_reader.interface;

    var it = msgs.iter();
    while (try it.next()) |msg| {
        switch (msg) {
            .prompt_echo_on => |p| {
                if (!ctx.termios.lflag.ECHO) {
                    ctx.termios.lflag.ECHO = true;
                    ctx.termios.lflag.ECHONL = false;
                    try std.posix.tcsetattr(std.posix.STDIN_FILENO, .FLUSH, ctx.termios);
                }
                try stdout.print("{s}", .{p.message});
                try stdout.flush();
                const input = (try stdin.takeDelimiter('\n')) orelse return error.EndOfStream;
                try p.respond(input);
            },
            .prompt_echo_off => |p| {
                if (ctx.termios.lflag.ECHO) {
                    ctx.termios.lflag.ECHO = false;
                    ctx.termios.lflag.ECHONL = true;
                    try std.posix.tcsetattr(std.posix.STDIN_FILENO, .FLUSH, ctx.termios);
                }
                try stdout.print("{s}", .{p.message});
                try stdout.flush();
                const input = (try stdin.takeDelimiter('\n')) orelse return error.EndOfStream;
                try p.respond(input);
            },
            .text_info => |text| {
                try stdout.print("{s}\n", .{text});
                try stdout.flush();
            },
            .error_msg => |text| {
                try stderr.print("{s}\n", .{text});
                try stderr.flush();
            },
        }
    }
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;

    var stderr_buf: [256]u8 = undefined;
    var stderr_writer = std.Io.File.stderr().writer(init.io, &stderr_buf);
    const stderr = &stderr_writer.interface;

    var args_it = init.minimal.args.iterate();
    _ = args_it.skip();

    const username = args_it.next() orelse {
        try stderr.print("usage: example <user>\n", .{});
        try stderr.flush();
        return;
    };

    const user_z = try allocator.dupeZ(u8, username);
    defer allocator.free(user_z);

    const termios = try std.posix.tcgetattr(std.posix.STDIN_FILENO);
    defer {
        std.posix.tcsetattr(std.posix.STDIN_FILENO, .FLUSH, termios) catch {};
    }

    var app = AppState{ .termios = termios, .io = init.io };

    var pam_client = try pam.Pam(AppState).init(allocator, .{
        .service_name = "login",
        .state = &.{
            .ctx = &app,
            .conv = conv,
        },
        .user = user_z,
    });
    defer pam_client.deinit();

    try pam_client.authenticate(.{});
    try pam_client.accountMgmt(.{});

    try stderr.print("Authentication Succeeded\n", .{});
    try stderr.flush();
}
