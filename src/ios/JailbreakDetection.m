//
//  JailbreakDetection.m
//  Copyright (c) 2014 Lee Crossley - http://ilee.co.uk
//  Techniques from http://highaltitudehacks.com/2013/12/17/ios-application-security-part-24-jailbreak-detection-and-evasion/
//

#import "Cordova/CDV.h"
#import "Cordova/CDVViewController.h"
#import "JailbreakDetection.h"
#import <dlfcn.h>
#import <sys/stat.h>
#import <netdb.h>
#import <mach-o/dyld.h>

#define FORMAT(format, ...) [NSString stringWithFormat:(format), ##__VA_ARGS__]

@implementation JailbreakDetection

- (void) isJailbroken:(CDVInvokedUrlCommand*)command;
{
    CDVPluginResult *pluginResult;

    @try
    {
        bool jailbroken = [self isNewJailBreak];
        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsBool:jailbroken];
    }
    @catch (NSException *exception)
    {
        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:exception.reason];
    }
    @finally
    {
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }
}

- (bool) jailbroken {

#if !(TARGET_IPHONE_SIMULATOR)

    if ([[NSFileManager defaultManager] fileExistsAtPath:@"/Applications/Cydia.app"])
    {
        return YES;
    }
    else if ([[NSFileManager defaultManager] fileExistsAtPath:@"/Library/MobileSubstrate/MobileSubstrate.dylib"])
    {
        return YES;
    }
    else if ([[NSFileManager defaultManager] fileExistsAtPath:@"/bin/bash"])
    {
        return YES;
    }
    else if ([[NSFileManager defaultManager] fileExistsAtPath:@"/usr/sbin/sshd"])
    {
        return YES;
    }
    else if ([[NSFileManager defaultManager] fileExistsAtPath:@"/etc/apt"])
    {
        return YES;
    }

    NSError *error;
    NSString *testWriteText = @"Jailbreak test";
    NSString *testWritePath = @"/private/jailbreaktest.txt";

    [testWriteText writeToFile:testWritePath atomically:YES encoding:NSUTF8StringEncoding error:&error];

    if (error == nil)
    {
        [[NSFileManager defaultManager] removeItemAtPath:testWritePath error:nil];
        return YES;
    }
    else
    {
        [[NSFileManager defaultManager] removeItemAtPath:testWritePath error:nil];
    }

    if ([[UIApplication sharedApplication] canOpenURL:[NSURL URLWithString:@"cydia://package/com.example.package"]])
    {
        return YES;
    }

#endif

    return NO;
}

- (BOOL) isNewJailBreak {
    //check runtime env
    char * env=getenv("DYLD_INSERT_LIBRARIES");
    
    if (env != nil) {
        //NSLog(@"env %s", env );
        return YES;
    }
    //Check folder access permissions
    if ([[NSFileManager defaultManager] fileExistsAtPath:@"/User/Applications"] ) {
        return YES;
    }
    //check system lib
    int ret;
    Dl_info dylib_info;
    NSString * libStr=@"/usr/lib/system/libsystem_kernel.dylib";
    int(* func_stat)(const char*, struct stat *)=stat;
    if ((ret = dladdr(func_stat, & dylib_info))) {
        //NSLog(@"lib:%s",dylib_info.dli_fname);
        if (![libStr isEqualToString: FORMAT(@"%s", dylib_info.dli_fname)]) {
            return YES;
        }
    }
    
    //Directory permissions checking
    NSArray * nameArray = @[@"/Applications/Cydia.app",
                            @"/Library/MobileSubstrate/MobileSubstrate.dylib",
                            @"/var/lib/cydia",
                            @"/var/cache/apt",
                            @"/var/lib/apt",
                            @"/etc/apt",
                            @"/bin/bash",
                            @"/bin/sh",
                            @"/usr/sbin/sshd",
                            @"/usr/libexec/ssh-keysign",
                            @"/etc/ssh/sshd_config"
                            ];
    
    struct stat s;
    for (NSString * fileName in nameArray) {
        const char * charFileName =[fileName UTF8String];
        if (stat(charFileName, & s) != -1) {
            return YES;
        }
    }
    
    //Process forking
    if (fork() != -1) {
        return YES;
    }
    
    NSError * error;
    NSString * stringToBeWritten=@"this is test";
    [stringToBeWritten writeToFile:@"/private/1.txt" atomically: YES encoding: NSUTF8StringEncoding error:& error];
    
    if (error == nil) {
        return YES;
    } else {
        [[NSFileManager defaultManager] removeItemAtPath:@"/private/1.txt" error: nil];
        
    }
    //dyld checking
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char * dyld = _dyld_get_image_name(i);
        int slength = strlen(dyld);
        
        int j;
        for (j = slength - 1; j >= 0; --j) {
            if (dyld[j] == '/') break;
        }
        
        NSString * dyldString =[NSString stringWithUTF8String: dyld];
        if ([dyldString hasSuffix:@"/Library/MobileSubstrate/MobileSubstrate.dylib"] ||
            [dyldString hasSuffix:@"/Library/MobileSubstrate/DynamicLibraries/xCon.dylib"]) {
            return YES;
        }
        
    }
    //Directory permissions checking
    NSArray * mutArray = @[@"/Applications/Cydia.app",
                           @"/Library/MobileSubstrate/MobileSubstrate.dylib",
                           @"/var/lib/cydia",
                           @"/var/cache/apt",
                           @"/var/lib/apt",
                           @"/etc/apt",
                           @"/bin/bash",
                           @"/bin/sh",
                           @"/usr/sbin/sshd",
                           @"/usr/libexec/ssh-keysign",
                           @"/etc/ssh/sshd_config",
                           @"/var/lib/xcon",
                           @"/Library/Wallpaper",
                           @"/usr/include",
                           @"/usr/libexec"
                           ];
    for (NSString * fName in mutArray) {
        FILE * output = fopen([fName UTF8String], "r");
        if (output) {
            fclose(output);
            return YES;
        }
        fclose(output);
    }
    
    
    @try {
        // Create socket
        int socketFileDescriptor = socket(AF_INET, SOCK_STREAM, 0);
        // Get IP address from host
        //
        struct hostent * remoteHostEnt = gethostbyname([@"127.0.0.1" UTF8String]);
        struct in_addr * remoteInAddr = (struct in_addr *) remoteHostEnt -> h_addr_list[0];
        
        // Set the socket parameters
        struct sockaddr_in socketParameters;
        socketParameters.sin_family = AF_INET;
        socketParameters.sin_addr = * remoteInAddr;
        socketParameters.sin_port = 22;
        
        // Connect the socket
        int ret = connect(socketFileDescriptor, (struct sockaddr *) & socketParameters, sizeof(socketParameters));
        if (-1 != ret) {
            close(socketFileDescriptor);
            return YES;
        } else {
            close(socketFileDescriptor);
        }
    }
    @catch (NSException * exception) {
    }
    
    return NO;
}
@end
