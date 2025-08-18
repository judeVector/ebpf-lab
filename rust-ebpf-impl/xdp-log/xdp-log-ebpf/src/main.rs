// #![no_std]
// #![no_main]

// use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
// use aya_log_ebpf::info;

// use core::mem;
// use network_types::{
//     eth::{EthHdr, EtherType},
//     ip::{IpProto, Ipv4Hdr},
//     tcp::TcpHdr,
//     udp::UdpHdr,
// };

// #[cfg(not(test))]
// #[panic_handler]
// fn panic(_info: &core::panic::PanicInfo) -> ! {
//     loop {}
// }

// #[xdp]
// pub fn xdp_firewall(ctx: XdpContext) -> u32 {
//     match try_xdp_firewall(ctx) {
//         Ok(ret) => ret,
//         Err(_) => xdp_action::XDP_ABORTED,
//     }
// }

// #[inline(always)] //
// fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
//     let start = ctx.data();
//     let end = ctx.data_end();
//     let len = mem::size_of::<T>();

//     if start + offset + len > end {
//         return Err(());
//     }

//     Ok((start + offset) as *const T)
// }

// fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
//     let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?; //
//     match unsafe { (*ethhdr).ether_type } {
//         EtherType::Ipv4 => {}
//         _ => return Ok(xdp_action::XDP_PASS),
//     }

//     let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
//     let source_addr = u32::from_be_bytes(unsafe { (*ipv4hdr).src_addr });

//     let source_port = match unsafe { (*ipv4hdr).proto } {
//         IpProto::Tcp => {
//             let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
//             u16::from_be(unsafe { (*tcphdr).source })
//         }
//         IpProto::Udp => {
//             let udphdr: *const UdpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
//             u16::from_be_bytes(unsafe { (*udphdr).source })
//         }
//         _ => return Err(()),
//     };

//     //
//     info!(&ctx, "SRC IP: {:i}, SRC PORT: {}", source_addr, source_port);

//     Ok(xdp_action::XDP_PASS)
// }

// To Drop Packets according to the Hashmap we have we use this
#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]

use core::mem;

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
};

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[map] // 
static BLOCKLIST: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(1024, 0);

#[xdp]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    let ptr = (start + offset) as *const T;
    Ok(unsafe { &*ptr })
}

//
fn block_ip(address: u32) -> bool {
    unsafe { BLOCKLIST.get(&address).is_some() }
}

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
    let source = u32::from_be_bytes(unsafe { (*ipv4hdr).src_addr });

    //
    let action = if block_ip(source) {
        xdp_action::XDP_DROP
    } else {
        xdp_action::XDP_PASS
    };
    info!(&ctx, "SRC: {:i}, ACTION: {}", source, action);

    Ok(action)
}
