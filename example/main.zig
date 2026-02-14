const std = @import("std");
const pam = @import("pam");

const AppState = struct {
    termios: std.posix.termios,
};

fn conv(allocator: std.mem.Allocator, msgs: pam.Messages, ctx: *AppState) anyerror!void {
    _ = allocator;
    var stdout_buf: [1024]u8 = undefined;
    var stderr_buf: [1024]u8 = undefined;
    var stdin_buf: [1024]u8 = undefined;
    var stdout_writer: std.fs.File.Writer = .init(std.fs.File.stdout(), &stdout_buf);
    var stderr_writer: std.fs.File.Writer = .init(std.fs.File.stderr(), &stderr_buf);
    var stdin_reader: std.fs.File.Reader = .init(std.fs.File.stdin(), &stdin_buf);
    const out = &stdout_writer.interface;
    const err = &stderr_writer.interface;
    const in = &stdin_reader.interface;

    var it = msgs.iter();
    while (try it.next()) |msg| {
        switch (msg) {
            .prompt_echo_on => |p| {
                if (!ctx.termios.lflag.ECHO) {
                    ctx.termios.lflag.ECHO = true;
                    try std.posix.tcsetattr(std.posix.STDIN_FILENO, .FLUSH, ctx.termios);
                }
                try out.print("{s}", .{p.message});
                try out.flush();
                const line = (try in.takeDelimiter('\n')) orelse return error.EndOfStream;
                try p.respond(std.mem.trimRight(u8, line, "\r"));
            },
            .prompt_echo_off => |p| {
                if (ctx.termios.lflag.ECHO) {
                    ctx.termios.lflag.ECHO = false;
                    try std.posix.tcsetattr(std.posix.STDIN_FILENO, .FLUSH, ctx.termios);
                }
                try out.print("{s}", .{p.message});
                try out.flush();
                const line = (try in.takeDelimiter('\n')) orelse return error.EndOfStream;
                try p.respond(std.mem.trimRight(u8, line, "\r"));
            },
            .text_info => |text| {
                try out.print("{s}\n", .{text});
                try out.flush();
            },
            .error_msg => |text| {
                try err.print("{s}\n", .{text});
                try err.flush();
            },
        }
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    var stderr_buf: [256]u8 = undefined;
    var stderr_writer: std.fs.File.Writer = .init(std.fs.File.stderr(), &stderr_buf);
    const stderr = &stderr_writer.interface;

    var args = try std.process.argsWithAllocator(allocator);
    defer args.deinit();
    _ = args.next();
    const username = args.next() orelse {
        try stderr.print("usage: example <user>\n", .{});
        try stderr.flush();
        return;
    };

    const user_z = try allocator.dupeZ(u8, username);
    defer allocator.free(user_z);

    var termios = try std.posix.tcgetattr(std.posix.STDIN_FILENO);
    defer {
        termios.lflag.ECHO = true;
        std.posix.tcsetattr(std.posix.STDIN_FILENO, .FLUSH, termios) catch {};
    }

    var app = AppState{ .termios = termios };
    var state = pam.Pam(AppState).ConvState{
        .ctx = &app,
        .conv = conv,
    };

    var pam_client = try pam.Pam(AppState).init(allocator, .{
        .service_name = "login",
        .state = &state,
        .user = user_z,
    });
    defer pam_client.deinit();

    try pam_client.authenticate(.{});
    try pam_client.accountMgmt(.{});

    try stderr.print("Authentication Succeeded\n", .{});
    try stderr.flush();
}
