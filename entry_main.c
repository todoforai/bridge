// Standalone entry for the todoforai-bridge executable.
// The real logic lives in bridge_main() (main.c) so the bridge can also be
// linked as a static library into host apps (e.g. the Tauri frontend), which
// re-expose it under their own argv dispatch (busybox-style).
int bridge_main(int argc, char **argv);

int main(int argc, char **argv) {
    return bridge_main(argc, argv);
}
