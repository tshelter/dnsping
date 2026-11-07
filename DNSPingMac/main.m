/*
 * DNS Ping — macOS AppKit prototype.
 *
 * Design reference: the Windows dnsping main window (dnsping/dnsping.c, dnsping/app.rc).
 * Same idea, same sections, native macOS UI. v0.1.0 scope, see PLANS/v0.1.0.md.
 */
#import <Cocoa/Cocoa.h>

@interface DNSPingAppDelegate : NSObject <NSApplicationDelegate>
@property (strong) NSWindow *window;
@property (weak) NSTextField *targetField;
@property (weak) NSComboBox *modeBox;
@property (weak) NSTextField *domainField;
@property (weak) NSComboBox *rateBox;
@property (weak) NSComboBox *durBox;
@property (weak) NSComboBox *tmoBox;
@property (weak) NSTextField *pathField;
@property (weak) NSButton *browseButton;
@property (weak) NSTextField *statusField;
@property (weak) NSView *graphView;
@property (weak) NSTextField *stats1Field;
@property (weak) NSTextField *stats2Field;
@property (weak) NSProgressIndicator *prog;
@property (weak) NSButton *startButton;
@property (weak) NSButton *analyzeButton;
@property (weak) NSButton *mtrButton;
@property (weak) NSButton *packButton;

@property (readwrite) BOOL running;
@property (strong) NSTimer *timer;
@end

@implementation DNSPingAppDelegate

- (void)applicationDidFinishLaunching:(NSNotification *)note {
    NSArray *modes = @[@"Cached name (0x20)", @"Random subdomain", @"ICMP ping", @"HTTP HEAD (curl -I)"];
    NSArray *rates = @[@"1 Hz (1 s)", @"2 Hz (500 ms)", @"5 Hz (200 ms)", @"10 Hz (100 ms)", @"20 Hz (50 ms)", @"50 Hz (20 ms)", @"100 Hz (10 ms)"];
    NSArray *durs = @[@"Unlimited", @"1 min", @"5 min", @"10 min", @"15 min", @"30 min", @"1 hour", @"2 hours"];
    NSArray *tmos = @[@"500 ms", @"1000 ms", @"2000 ms"];

    NSWindow *w = [[NSWindow alloc] initWithContentRect:NSMakeRect(0, 0, 440, 430)
                                               styleMask:NSWindowStyleMaskTitled | NSWindowStyleMaskClosable | NSWindowStyleMaskMiniaturizable | NSWindowStyleMaskResizable
                                                 backing:NSBackingStoreBuffered
                                                   defer:NO];
    [w setTitle:@"DNS Ping"];
    [w center];
    [w setMinSize:NSMakeSize(440, 430)];
    [self setWindow:w];

    NSView *cv = [w contentView];
    [cv setWantsLayer:YES];

    NSTextField *h1 = [self label:@"Target"];
    [h1 setFrame:NSMakeRect(12, 392, 234, 14)];
    [cv addSubview:h1];
    [self setTargetField:[self textfieldWithPlaceholder:@"DNS server / host for ICMP / URL for HTTP"]];
    [self.targetField setFrame:NSMakeRect(12, 370, 320, 22)];
    [cv addSubview:self.targetField];

    NSTextField *modeLabel = [self label:@"Query mode"];
    [modeLabel setFrame:NSMakeRect(12, 344, 90, 14)];
    [cv addSubview:modeLabel];
    NSTextField *domainLabel = [self label:@"Domain"];
    [domainLabel setFrame:NSMakeRect(222, 344, 70, 14)];
    [cv addSubview:domainLabel];
    [self setModeBox:[self comboboxWithItems:modes]];
    [self.modeBox setFrame:NSMakeRect(12, 322, 150, 22)];
    [self.modeBox setEnabled:YES];
    [cv addSubview:self.modeBox];
    [self setDomainField:[self textfieldWithPlaceholder:@"google.com"]];
    [self.domainField setFrame:NSMakeRect(222, 322, 110, 22)];
    [cv addSubview:self.domainField];
    [[self.domainField cell] setEditable:YES];

    NSTextField *rateLabel = [self label:@"Rate"];
    [rateLabel setFrame:NSMakeRect(12, 296, 70, 14)];
    [cv addSubview:rateLabel];
    NSTextField *durLabel = [self label:@"Duration"];
    [durLabel setFrame:NSMakeRect(130, 296, 70, 14)];
    [cv addSubview:durLabel];
    NSTextField *tmoLabel = [self label:@"Timeout"];
    [tmoLabel setFrame:NSMakeRect(248, 296, 70, 14)];
    [cv addSubview:tmoLabel];
    [self setRateBox:[self comboboxWithItems:rates]];
    [self.rateBox setFrame:NSMakeRect(12, 274, 110, 22)];
    [cv addSubview:self.rateBox];
    [self setDurBox:[self comboboxWithItems:durs]];
    [self.durBox setFrame:NSMakeRect(130, 274, 110, 22)];
    [cv addSubview:self.durBox];
    [self setTmoBox:[self comboboxWithItems:tmos]];
    [self.tmoBox setFrame:NSMakeRect(248, 274, 110, 22)];
    [cv addSubview:self.tmoBox];
    [self.rateBox selectItemAtIndex:3];
    [self.durBox selectItemAtIndex:3];
    [self.tmoBox selectItemAtIndex:1];

    NSTextField *pathLabel = [self label:@"Output folder"];
    [pathLabel setFrame:NSMakeRect(12, 246, 234, 14)];
    [cv addSubview:pathLabel];
    [self setPathField:[self textfieldWithPlaceholder:@""]];
    [self.pathField setFrame:NSMakeRect(12, 224, 300, 22)];
    [cv addSubview:self.pathField];
    [self setBrowseButton:[self buttonWithTitle:@"..." target:self action:@selector(browsePath:)]];
    [self.browseButton setFrame:NSMakeRect(320, 224, 28, 22)];
    [cv addSubview:self.browseButton];

    NSTextField *statusLabel = [self label:@"Status"];
    [statusLabel setFrame:NSMakeRect(12, 200, 234, 14)];
    [cv addSubview:statusLabel];
    [self setStatusField:[[NSTextField alloc] initWithFrame:NSMakeRect(12, 184, 416, 16)]];
    [self.statusField setBezeled:NO];
    [self.statusField setDrawsBackground:NO];
    [self.statusField setStringValue:@"Ready"];
    [cv addSubview:self.statusField];

    [self setGraphView:[self opaqueView]];
    [self.graphView setFrame:NSMakeRect(12, 120, 416, 60)];
    [self.graphView setBackgroundColor:[NSColor colorWithWhite:0.97 alpha:1]];
    [cv addSubview:self.graphView];

    [self setStats1Field:[self label:@""]];
    [self.stats1Field setFrame:NSMakeRect(12, 96, 416, 14)];
    [cv addSubview:self.stats1Field];
    [self setStats2Field:[self label:@""]];
    [self.stats2Field setFrame:NSMakeRect(12, 80, 416, 14)];
    [cv addSubview:self.stats2Field];

    [self setProg:[NSProgressIndicator progressIndicatorWithStyle:NSProgressIndicatorBarStyle]];
    [self.prog setFrame:NSMakeRect(12, 64, 416, 10)];
    [self.prog setMinValue:0];
    [self.prog setMaxValue:1000];
    [self.prog setIndeterminate:YES];
    [cv addSubview:self.prog];

    NSButton *analyze = [self buttonWithTitle:@"Analyze..." target:self action:@selector(analyze:)];
    [analyze setFrame:NSMakeRect(12, 30, 74, 22)];
    [cv addSubview:analyze];
    [self setAnalyzeButton:analyze];
    NSButton *mtr = [self buttonWithTitle:@"MTR..." target:self action:@selector(mtr:)];
    [mtr setFrame:NSMakeRect(96, 30, 54, 22)];
    [cv addSubview:mtr];
    [self setMtrButton:mtr];
    NSButton *pack = [self buttonWithTitle:@"Pack & share" target:self action:@selector(pack:)];
    [pack setFrame:NSMakeRect(160, 30, 90, 22)];
    [cv addSubview:pack];
    [self setPackButton:pack];
    NSButton *start = [self buttonWithTitle:@"START" target:self action:@selector(start:)];
    [start setFrame:NSMakeRect(262, 30, 74, 22)];
    [cv addSubview:start];
    [self setStartButton:start];
    [start setKeyEquivalent:@"\r"];
    NSButton *close = [self buttonWithTitle:@"Close" target:self action:@selector(close:)];
    [close setFrame:NSMakeRect(346, 30, 74, 22)];
    [cv addSubview:close];

    [w makeKeyAndOrderFront:nil];
}

- (NSTextField *)label:(NSString *)s {
    NSTextField *f = [[NSTextField alloc] initWithFrame:NSZeroRect];
    [f setStringValue:s];
    [f setBezeled:NO];
    [f setDrawsBackground:NO];
    [f setFont:[NSFont systemFontOfSize:11]];
    return f;
}

- (NSTextField *)textfieldWithPlaceholder:(NSString *)placeholder {
   NSTextField *f = [[NSTextField alloc] initWithFrame:NSZeroRect];
    [f setPlaceholderString:placeholder];
    [f setBezeled:YES];
    [f setWantsLayer:YES];
    return f;
}

- (NSComboBox *)comboboxWithItems:(NSArray *)items {
    NSComboBox *b = [[NSComboBox alloc] initWithFrame:NSZeroRect];
    for (NSString *it in items) [b addItemWithObjectValue:it];
    [b setBezeled:YES];
    [b setPrototypeDisplayValue:@"100 Hz (10 ms)"];
    return b;
}

- (NSButton *)buttonWithTitle:(NSString *)title target:(id)t action:(SEL)a {
    NSButton *b = [[NSButton alloc] initWithFrame:NSZeroRect];
    [b setTitle:title];
    [b setBezelStyle:NSBezelStyleRounded];
    [b setTarget:t];
    [b setAction:a];
    return b;
}

- (NSView *)opaqueView {
    NSView *v = [[NSView alloc] initWithFrame:NSZeroRect];
    [v setWantsLayer:YES];
    return v;
}

- (void)modeChanged {
    NSInteger m = [self.modeBox indexOfSelectedItem];
    [self.domainField setEditable:(m < 2)];
}

- (void)validateStart {
    BOOL run = self.running;
    [self.startButton setTitle:run ? @"STOP" : @"START"];
    [self.prog setIndeterminate:(run ? ([self.durBox indexOfSelectedItem] == 0) : NO)];
    if (!run) {
        [self.prog setDoubleValue:0];
        [self.stats1Field setStringValue:@""];
        [self.stats2Field setStringValue:@""];
        [self.statusField setStringValue:@"Ready"];
    }
    [self.analyzeButton setEnabled:YES];
    [self.mtrButton setEnabled:YES];
    [self.packButton setEnabled:YES];
    [self.targetField setEditable:!run];
    [self.modeBox setEnabled:!run];
    [self.domainField setEditable:!run && ([self.modeBox indexOfSelectedItem] < 2)];
    [self.rateBox setEnabled:!run];
    [self.durBox setEnabled:!run];
    [self.tmoBox setEnabled:!run];
    [self.pathField setEditable:!run];
    [self.browseButton setEnabled:!run];
    [self.startButton setEnabled:YES];
}

- (void)start:(id)sender {
    if (self.running) {
        [self stop];
        return;
    }
    [self validateStart];
    // Real probe startup lives in the shared core; this prototype mirrors the Windows flow and
    // leaves the actual DNS/ICMP/HTTP backend for the platform-native core.
    [self setRunning:YES];
    [self validateStart];
    [self.statusField setStringValue:@"Starting..."];
    // Placeholder runner so the UI demonstrates the flow.
    __weak typeof(self) wself = self;
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        for (int i = 0; i < 10 && wself.running; i++) {
            double v = 8 + (double)(arc4random_uniform(40));
            dispatch_async(dispatch_get_main_queue(), ^{
                [wself.prog setDoubleValue:(wself.prog.doubleValue + v)];
                NSMutableString *s = [NSMutableString string];
                [s appendFormat:@"Ping: now %.1f ms", v];
                [wself.stats1Field setStringValue:s];
                [s setString:@""];
                [s appendFormat:@"Probes %d   Lost 0 (0.00%%)   Jitter 0.0 ms", i + 1];
                [wself.stats2Field setStringValue:s];
                [wself updateGraphSample:v];
            });
            [NSThread sleepForTimeInterval:0.1];
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            wself.running = NO;
            [wself validateStart];
            [wself.statusField setStringValue:@"Finishing: saving files..."];
            [NSThread sleepForTimeInterval:0.4];
            [wself.prog setDoubleValue:0];
            [wself.stats2Field setStringValue:[NSString stringWithFormat:@"Saved 10 probes to session folder"]];
            [wself validateStart];
        });
    });
}

- (void)stop {
    self.running = NO;
    if (self.timer) { [self.timer invalidate]; self.timer = nil; }
    [self validateStart];
}

- (void)browsePath:(id)sender {
    NSOpenPanel *p = [NSOpenPanel openPanel];
    [p setCanChooseDirectories:YES];
    [p setCanChooseFiles:NO];
    [p setPrompt:@"Choose"];
    if ([p runModal] == NSModalResponseOK) {
        [self.pathField setStringValue:[[p URL] path]];
    }
}

- (void)updateGraphSample:(double)val {
    NSView *v = self.graphView;
    [v setNeedsDisplay:YES];
}

- (void)drawRect:(NSRect)rect {
    // Graph drawing lives on the graph view; placeholder for now.
}

- (void)analyze:(id)sender { [self.statusField setStringValue:@"Analyze... (placeholder)"]; }
- (void)mtr:(id)sender     { [self.statusField setStringValue:@"MTR... (placeholder)"]; }
- (void)pack:(id)sender     { [self.statusField setStringValue:@"Pack & share (placeholder)"]; }
- (void)close:(id)sender    { [NSApp terminate:nil]; }

@end

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        NSApplication *app = [NSApplication sharedApplication];
        [app setActivationPolicy:NSApplicationActivationPolicyRegular];
        DNSPingAppDelegate *d = [[DNSPingAppDelegate alloc] init];
        [app setDelegate:d];
        [app run];
    }
    return 0;
}
