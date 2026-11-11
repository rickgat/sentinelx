//! Ad-hoc driver for the same-origin web-application crawler.
//!
//! Enumerates endpoints reachable from a start URL (anchors, form
//! actions/methods, script srcs) without needing a Postman collection.
//! Same-origin only, robots-respecting, rate-limited — the crawler's own
//! safeguards apply.
//!
//! Usage: `cargo run -p sx-discovery --example crawl -- <url> [max_depth] [max_urls]`

// Operator-facing CLI example: stdout is the product and fail-fast on bad
// arguments is the desired UX, so the workspace print/expect denies are
// relaxed for this file only.
#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::expect_used,
    clippy::disallowed_macros
)]

use std::env;
use std::time::Duration;

use sx_discovery::scanner::webapp_crawler::WebappCrawler;
use url::Url;

#[tokio::main]
async fn main() {
    let mut args = env::args().skip(1);
    let target = args
        .next()
        .expect("usage: crawl <url> [max_depth] [max_urls]");
    let max_depth: u32 = args.next().and_then(|s| s.parse().ok()).unwrap_or(2);
    let max_urls: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(100);

    let start = Url::parse(&target).expect("invalid start URL");

    let http = reqwest::Client::builder()
        .user_agent("SentinelX-WebCrawler/0.1 (authorized staging recon)")
        .timeout(Duration::from_secs(10))
        .build()
        .expect("failed to build reqwest client");

    let crawler = WebappCrawler::new(http, max_depth, max_urls, true);

    println!("== crawling {start} (max_depth={max_depth}, max_urls={max_urls}, respect_robots=true) ==\n");

    match crawler.crawl(start).await {
        Ok(rep) => {
            println!("visited pages: {}", rep.visited.len());
            let mut total_forms = 0usize;
            let mut total_scripts = 0usize;
            for p in &rep.visited {
                println!("\n[{}] {}", p.status, p.url);
                for f in &p.forms {
                    total_forms += 1;
                    let action = f.action.as_ref().map_or("(self)", Url::as_str);
                    println!("    FORM   {:<6} action={action}", f.method);
                }
                for s in &p.scripts {
                    total_scripts += 1;
                    println!("    SCRIPT {s}");
                }
                for l in &p.links {
                    println!("    LINK   {l}");
                }
            }
            println!("\n---- summary ----");
            println!("pages fetched     : {}", rep.visited.len());
            println!("forms discovered  : {total_forms}");
            println!("scripts discovered: {total_scripts}");
            println!(
                "out-of-scope/blocked URLs: {}",
                rep.queued_outside_scope.len()
            );
            for u in &rep.queued_outside_scope {
                println!("    OOS {u}");
            }
        }
        Err(e) => eprintln!("crawl error: {e}"),
    }
}
