import React, { useEffect, useMemo, useState } from 'react';
import {
  ArrowLeft,
  ArrowRight,
  BookOpen,
  Calendar,
  Check,
  Clock,
  Copy,
  FileCode,
  Search,
  Shield,
  ShieldCheck,
  Sparkles,
  Terminal,
  X,
} from 'lucide-react';
import {
  BLOG_CATEGORIES,
  BLOG_POSTS,
  getBlogPostBySlug,
  type BlogCategory,
  type BlogPost,
} from '../data/blogPosts';

interface BlogPageProps {
  activeSlug: string | null;
  onSelectPost: (slug: string) => void;
  onBackToList: () => void;
  onStartAudit: () => void;
}

const DEFAULT_TITLE = 'CheckMyAPK — Free Android APK Decompiler & Website Vulnerability Scanner';
const DEFAULT_DESC =
  'Zero-install OWASP MASVS Android APK decompiler, secret scanner, and live website & API vulnerability scanner. Detect leaked API keys, TLS/CORS misconfigurations, and debug backdoors in seconds.';

function setMetaTag(selector: string, attr: 'content' | 'href', value: string) {
  const el = document.querySelector(selector);
  if (el) el.setAttribute(attr, value);
}

const CATEGORY_ACCENT: Record<BlogCategory, string> = {
  'Android APK': 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
  'Web & API': 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30',
  'Cloud & BaaS': 'bg-amber-500/10 text-amber-400 border-amber-500/30',
  'Play Store Compliance': 'bg-violet-500/10 text-violet-300 border-violet-500/30',
};

export const BlogPage: React.FC<BlogPageProps> = ({
  activeSlug,
  onSelectPost,
  onBackToList,
  onStartAudit,
}) => {
  const [selectedCategory, setSelectedCategory] = useState<'All' | BlogCategory>('All');
  const [searchQuery, setSearchQuery] = useState('');
  const [copiedCode, setCopiedCode] = useState(false);

  const activePost: BlogPost | null = useMemo(
    () => getBlogPostBySlug(activeSlug),
    [activeSlug]
  );

  // Sync document title, meta description, canonical, OG tags & Article JSON-LD
  useEffect(() => {
    const title = activePost
      ? activePost.metaTitle
      : 'Security Blog & Remediation Guides | CheckMyAPK';
    const description = activePost
      ? activePost.metaDescription
      : 'Practical Android APK security, OWASP MASVS v2, HTTP headers, CORS, JWT, and cloud BaaS remediation guides with copy-paste fixes.';
    const canonical = activePost
      ? `https://checkmyapk.com/blog/${activePost.slug}`
      : 'https://checkmyapk.com/blog';

    document.title = title;
    setMetaTag('meta[name="description"]', 'content', description);
    setMetaTag('meta[property="og:title"]', 'content', title);
    setMetaTag('meta[property="og:description"]', 'content', description);
    setMetaTag('meta[property="og:url"]', 'content', canonical);
    setMetaTag('meta[name="twitter:title"]', 'content', title);
    setMetaTag('meta[name="twitter:description"]', 'content', description);
    setMetaTag('link[rel="canonical"]', 'href', canonical);

    const existingScript = document.getElementById('checkmyapk-blog-jsonld');
    if (existingScript) existingScript.remove();

    if (activePost) {
      const ldScript = document.createElement('script');
      ldScript.id = 'checkmyapk-blog-jsonld';
      ldScript.type = 'application/ld+json';
      ldScript.textContent = JSON.stringify({
        '@context': 'https://schema.org',
        '@graph': [
          {
            '@type': 'TechArticle',
            headline: activePost.title,
            description: activePost.metaDescription,
            datePublished: activePost.publishedAt,
            dateModified: activePost.publishedAt,
            author: { '@type': 'Organization', name: 'CheckMyAPK Security Team' },
            publisher: {
              '@type': 'Organization',
              name: 'CheckMyAPK',
              url: 'https://checkmyapk.com',
            },
            mainEntityOfPage: canonical,
            keywords: activePost.keywords.join(', '),
          },
          ...(activePost.faqs.length > 0
            ? [
                {
                  '@type': 'FAQPage',
                  mainEntity: activePost.faqs.map((f) => ({
                    '@type': 'Question',
                    name: f.q,
                    acceptedAnswer: { '@type': 'Answer', text: f.a },
                  })),
                },
              ]
            : []),
        ],
      });
      document.head.appendChild(ldScript);
    }

    return () => {
      document.title = DEFAULT_TITLE;
      setMetaTag('meta[name="description"]', 'content', DEFAULT_DESC);
      setMetaTag('meta[property="og:title"]', 'content', DEFAULT_TITLE);
      setMetaTag('meta[property="og:description"]', 'content', DEFAULT_DESC);
      setMetaTag('meta[property="og:url"]', 'content', 'https://checkmyapk.com/');
      setMetaTag('meta[name="twitter:title"]', 'content', DEFAULT_TITLE);
      setMetaTag('meta[name="twitter:description"]', 'content', DEFAULT_DESC);
      setMetaTag('link[rel="canonical"]', 'href', 'https://checkmyapk.com/');
      const s = document.getElementById('checkmyapk-blog-jsonld');
      if (s) s.remove();
    };
  }, [activePost]);

  const filteredPosts = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return BLOG_POSTS.filter((post) => {
      if (selectedCategory !== 'All' && post.category !== selectedCategory) return false;
      if (!q) return true;
      const hay = `${post.title} ${post.excerpt} ${post.owaspRef} ${post.keywords.join(' ')}`.toLowerCase();
      return hay.includes(q);
    });
  }, [selectedCategory, searchQuery]);

  const relatedPosts = useMemo(() => {
    if (!activePost) return [];
    const sameCat = BLOG_POSTS.filter(
      (p) => p.slug !== activePost.slug && p.category === activePost.category
    );
    const others = BLOG_POSTS.filter(
      (p) => p.slug !== activePost.slug && p.category !== activePost.category
    );
    return [...sameCat, ...others].slice(0, 3);
  }, [activePost]);

  const handleCopyPatch = (code: string) => {
    navigator.clipboard.writeText(code);
    setCopiedCode(true);
    setTimeout(() => setCopiedCode(false), 1800);
  };

  // ── ARTICLE READER VIEW (/blog/:slug) ──
  if (activePost) {
    return (
      <article className="w-full max-w-4xl mx-auto py-8 sm:py-12 space-y-8 text-left">
        {/* Top Back Navigation */}
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <button
            type="button"
            onClick={onBackToList}
            className="inline-flex items-center gap-1.5 font-mono text-xs text-slate-400 hover:text-emerald-400 transition-colors cursor-pointer"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            <span>Back to all {BLOG_POSTS.length} security guides</span>
          </button>

          <button
            type="button"
            onClick={onStartAudit}
            className="wb-emerald-btn h-8 px-3.5 rounded-md text-[11.5px] font-semibold inline-flex items-center gap-1.5 cursor-pointer"
          >
            <Shield className="w-3.5 h-3.5" />
            <span>Scan Your APK / URL</span>
          </button>
        </div>

        {/* Article Header Card */}
        <div className="wb-bezel p-1.5 rounded-2xl relative">
          <div
            aria-hidden="true"
            className="pointer-events-none absolute inset-x-10 top-0 h-px bg-gradient-to-r from-transparent via-emerald-400/50 to-transparent"
          />
          <header className="wb-surface rounded-xl p-6 sm:p-8 space-y-5">
            <div className="flex items-center gap-2 flex-wrap font-mono text-[10.5px]">
              <span
                className={`px-2 py-0.5 rounded border font-semibold ${CATEGORY_ACCENT[activePost.category]}`}
              >
                {activePost.category}
              </span>
              <span className="px-2 py-0.5 rounded wb-spec-code font-medium">
                {activePost.owaspRef}
              </span>
              <span className="inline-flex items-center gap-1 text-slate-400">
                <Calendar className="w-3 h-3" />
                {activePost.publishedAt}
              </span>
              <span className="text-slate-600">·</span>
              <span className="inline-flex items-center gap-1 text-slate-400">
                <Clock className="w-3 h-3" />
                {activePost.readTime}
              </span>
            </div>

            <h1 className="text-2xl sm:text-4xl font-display font-bold tracking-[-0.025em] text-white leading-tight">
              {activePost.title}
            </h1>

            <p className="text-sm sm:text-base text-slate-300 leading-relaxed">
              {activePost.excerpt}
            </p>

            {/* TL;DR Key Takeaways */}
            <div className="wb-ide-evidence rounded-xl border border-emerald-500/25 p-4 sm:p-5 space-y-2.5">
              <div className="flex items-center gap-2 font-mono text-[10.5px] uppercase tracking-[0.14em] font-semibold text-emerald-400">
                <Sparkles className="w-3.5 h-3.5" />
                <span>Key Takeaways</span>
              </div>
              <ul className="space-y-2 text-xs sm:text-[13px] text-slate-300 leading-relaxed">
                {activePost.summaryPoints.map((pt, idx) => (
                  <li key={idx} className="flex items-start gap-2.5">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 mt-1.5 shrink-0" />
                    <span>{pt}</span>
                  </li>
                ))}
              </ul>
            </div>
          </header>
        </div>

        {/* Article Body Sections */}
        <div className="wb-surface rounded-2xl p-6 sm:p-8 space-y-8">
          {activePost.sections.map((sec, idx) => (
            <section key={idx} className="space-y-3.5">
              <h2 className="text-lg sm:text-xl font-display font-semibold text-white tracking-[-0.015em] flex items-center gap-2.5">
                <span className="font-mono text-[11px] text-emerald-400 bg-emerald-500/10 border border-emerald-500/25 px-2 py-0.5 rounded">
                  0{idx + 1}
                </span>
                <span>{sec.heading}</span>
              </h2>
              {sec.body.map((p, pIdx) => (
                <p key={pIdx} className="text-sm text-slate-300 leading-relaxed">
                  {p}
                </p>
              ))}
              {sec.bullets && sec.bullets.length > 0 && (
                <ul className="space-y-2 pt-1 pl-1">
                  {sec.bullets.map((b, bIdx) => (
                    <li key={bIdx} className="flex items-start gap-2.5 text-sm text-slate-300 leading-relaxed">
                      <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 mt-2 shrink-0" />
                      <span>{b}</span>
                    </li>
                  ))}
                </ul>
              )}
            </section>
          ))}

          {/* Before vs After Code Patch Workbench */}
          <section className="pt-4 border-t border-white/10 space-y-4">
            <div className="flex items-center justify-between gap-2 flex-wrap">
              <h2 className="text-lg font-display font-semibold text-white inline-flex items-center gap-2">
                <FileCode className="w-4 h-4 text-emerald-400" />
                <span>Copy-Paste Production Fix</span>
              </h2>
              <span className="font-mono text-[11px] text-slate-400">
                {activePost.codeDiff.filename}
              </span>
            </div>

            <div className="space-y-3">
              {/* Vulnerable Before */}
              <div className="rounded-xl border border-rose-500/25 overflow-hidden">
                <div className="px-3.5 py-2 wb-diff-del border-b border-rose-500/20 font-mono text-[10.5px] font-semibold">
                  - Vulnerable Configuration
                </div>
                <pre className="p-3.5 wb-diff-del font-mono text-[11.5px] overflow-x-auto leading-relaxed select-all">
                  {activePost.codeDiff.before}
                </pre>
              </div>

              {/* Hardened After */}
              <div className="rounded-xl border border-emerald-500/30 overflow-hidden wb-surface-muted">
                <div className="wb-ide-chrome px-3.5 py-2 border-b border-white/10 flex items-center justify-between gap-2 font-mono text-[10.5px]">
                  <span className="text-emerald-400 font-semibold">
                    + Hardened Fix · {activePost.codeDiff.filename}
                  </span>
                  <button
                    type="button"
                    onClick={() => handleCopyPatch(activePost.codeDiff.after)}
                    className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-emerald-500/10 hover:bg-emerald-500/20 border border-emerald-500/30 text-emerald-400 font-semibold cursor-pointer"
                  >
                    {copiedCode ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                    <span>{copiedCode ? 'Copied' : 'Copy Fix'}</span>
                  </button>
                </div>
                <pre className="p-3.5 text-emerald-300 font-mono text-[11.5px] overflow-x-auto leading-relaxed select-all">
                  {activePost.codeDiff.after}
                </pre>
              </div>

              {/* Verify Command */}
              <div className="px-3.5 py-2.5 rounded-xl wb-ide-evidence border border-white/10 flex items-center gap-2 font-mono text-[11px] text-slate-400 overflow-x-auto">
                <Terminal className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                <span className="shrink-0 text-slate-500">Verify:</span>
                <code className="text-cyan-400 select-all">{activePost.codeDiff.verifyCommand}</code>
              </div>
            </div>
          </section>

          {/* Mini FAQ Section */}
          {activePost.faqs.length > 0 && (
            <section className="pt-4 border-t border-white/10 space-y-3.5">
              <h2 className="text-lg font-display font-semibold text-white">
                Frequently Asked Questions
              </h2>
              <div className="space-y-3">
                {activePost.faqs.map((faq, idx) => (
                  <div
                    key={idx}
                    className="p-4 rounded-xl wb-surface-muted border border-white/10 space-y-1.5"
                  >
                    <h3 className="text-sm font-semibold text-white">{faq.q}</h3>
                    <p className="text-xs sm:text-[13px] text-slate-300 leading-relaxed">{faq.a}</p>
                  </div>
                ))}
              </div>
            </section>
          )}
        </div>

        {/* Inline Conversion CTA Card */}
        <div className="wb-bezel p-1.5 rounded-2xl relative">
          <div
            aria-hidden="true"
            className="pointer-events-none absolute inset-x-10 top-0 h-px bg-gradient-to-r from-transparent via-emerald-400/60 to-transparent"
          />
          <div className="wb-surface rounded-xl p-6 sm:p-7 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="space-y-1.5">
              <div className="inline-flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-[0.14em] text-emerald-400 font-semibold">
                <ShieldCheck className="w-3.5 h-3.5" />
                <span>Automated Verification</span>
              </div>
              <h3 className="text-lg font-display font-semibold text-white">
                Check if your APK or website has this issue right now
              </h3>
              <p className="text-xs sm:text-sm text-slate-400">
                Run 45+ deterministic OWASP MASVS &amp; web security rules in 10 seconds with zero server retention.
              </p>
            </div>
            <button
              type="button"
              onClick={onStartAudit}
              className="wb-emerald-btn h-10 px-5 rounded-lg text-xs font-semibold inline-flex items-center justify-center gap-2 shrink-0 cursor-pointer"
            >
              <span>Run Free Security Audit</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Related Guides */}
        <section className="space-y-4">
          <h2 className="font-mono text-xs uppercase tracking-[0.14em] text-slate-400 font-semibold">
            Related Security Guides
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {relatedPosts.map((rel) => (
              <button
                key={rel.slug}
                type="button"
                onClick={() => onSelectPost(rel.slug)}
                className="wb-surface rounded-xl p-4 text-left hover:border-emerald-500/40 transition-all flex flex-col justify-between gap-3 cursor-pointer group"
              >
                <div className="space-y-2">
                  <span
                    className={`inline-block font-mono text-[9.5px] px-2 py-0.5 rounded border ${CATEGORY_ACCENT[rel.category]}`}
                  >
                    {rel.category}
                  </span>
                  <h3 className="text-sm font-display font-semibold text-white group-hover:text-emerald-400 transition-colors leading-snug">
                    {rel.title}
                  </h3>
                </div>
                <span className="font-mono text-[10.5px] text-emerald-400 inline-flex items-center gap-1">
                  <span>Read guide</span>
                  <ArrowRight className="w-3 h-3" />
                </span>
              </button>
            ))}
          </div>
        </section>
      </article>
    );
  }

  // ── BLOG INDEX HUB (/blog) ──
  return (
    <div className="w-full max-w-6xl mx-auto py-8 sm:py-12 space-y-8 text-left">
      {/* Header */}
      <div className="space-y-4 text-center max-w-3xl mx-auto">
        <div className="wb-eyebrow-pill inline-flex items-center gap-2 px-3 py-1 rounded-md font-mono text-[11px] font-medium">
          <BookOpen className="w-3.5 h-3.5 text-emerald-400" />
          <span>SECURITY RESEARCH · {BLOG_POSTS.length} GUIDES</span>
        </div>

        <h1 className="text-3xl sm:text-5xl font-display font-bold tracking-[-0.03em] text-white leading-tight">
          Security Guides &amp; <span className="text-emerald-400">Remediation Playbooks.</span>
        </h1>

        <p className="text-sm sm:text-base text-slate-400 leading-relaxed">
          Deep-dive engineering tutorials for fixing OWASP MASVS v2 Android APK findings, leaked API keys, HTTP headers, CORS, JWTs, and cloud BaaS exposures.
        </p>
      </div>

      {/* Filter & Search Toolbar */}
      <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3">
        <div className="flex items-center gap-1.5 flex-wrap">
          {BLOG_CATEGORIES.map((cat) => {
            const count =
              cat === 'All'
                ? BLOG_POSTS.length
                : BLOG_POSTS.filter((p) => p.category === cat).length;
            const active = selectedCategory === cat;
            return (
              <button
                key={cat}
                type="button"
                onClick={() => setSelectedCategory(cat)}
                className={`px-3 py-1.5 rounded-md font-mono text-[11px] font-medium border transition-colors cursor-pointer ${
                  active
                    ? 'bg-emerald-500/15 border-emerald-500/40 text-emerald-400 font-semibold'
                    : 'bg-white/[0.03] border-white/10 text-slate-400 hover:text-white'
                }`}
              >
                {cat} ({count})
              </button>
            );
          })}
        </div>

        <div className="relative min-w-[220px] md:w-72">
          <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 pointer-events-none" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search guides (e.g. CSP, APK, JWT)..."
            className="w-full h-9 pl-9 pr-8 rounded-lg font-mono text-xs bg-black/40 border border-white/15 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500/60"
          />
          {searchQuery && (
            <button
              type="button"
              onClick={() => setSearchQuery('')}
              className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-white cursor-pointer"
              aria-label="Clear search"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </div>

      {/* Articles Grid */}
      {filteredPosts.length === 0 ? (
        <div className="wb-surface rounded-2xl p-12 text-center text-slate-400 text-sm">
          No security guides matched &quot;{searchQuery}&quot;. Try clearing the filter.
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {filteredPosts.map((post, idx) => (
            <article
              key={post.slug}
              onClick={() => onSelectPost(post.slug)}
              className="wb-surface rounded-xl p-5 sm:p-6 hover:border-emerald-500/40 transition-all flex flex-col justify-between gap-4 cursor-pointer group"
            >
              <div className="space-y-3">
                <div className="flex items-center justify-between gap-2 flex-wrap font-mono text-[10px]">
                  <div className="flex items-center gap-2">
                    <span className="text-slate-500 tabular-nums">
                      {String(idx + 1).padStart(2, '0')}
                    </span>
                    <span
                      className={`px-2 py-0.5 rounded border font-semibold ${CATEGORY_ACCENT[post.category]}`}
                    >
                      {post.category}
                    </span>
                    <span className="px-2 py-0.5 rounded wb-spec-code">
                      {post.owaspRef}
                    </span>
                  </div>
                  <span className="text-slate-500">{post.readTime}</span>
                </div>

                <h2 className="text-base sm:text-lg font-display font-semibold text-white group-hover:text-emerald-400 transition-colors leading-snug">
                  {post.title}
                </h2>

                <p className="text-xs sm:text-[13px] text-slate-400 leading-relaxed line-clamp-2">
                  {post.excerpt}
                </p>
              </div>

              <div className="pt-3 border-t border-white/10 flex items-center justify-between font-mono text-[11px]">
                <span className="text-slate-500">{post.publishedAt}</span>
                <span className="text-emerald-400 font-semibold inline-flex items-center gap-1 group-hover:translate-x-0.5 transition-transform">
                  <span>Read Playbook</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </span>
              </div>
            </article>
          ))}
        </div>
      )}

      {/* Bottom Scanner CTA */}
      <div className="wb-bezel p-1.5 rounded-2xl relative">
        <div
          aria-hidden="true"
          className="pointer-events-none absolute inset-x-10 top-0 h-px bg-gradient-to-r from-transparent via-emerald-400/50 to-transparent"
        />
        <div className="wb-surface rounded-xl p-6 sm:p-8 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="space-y-1">
            <h2 className="text-lg sm:text-xl font-display font-semibold text-white">
              Ready to audit your own Android APK or Web App?
            </h2>
            <p className="text-xs sm:text-sm text-slate-400">
              Every vulnerability covered in these {BLOG_POSTS.length} guides is automatically checked by CheckMyAPK.
            </p>
          </div>
          <button
            type="button"
            onClick={onStartAudit}
            className="wb-emerald-btn h-10 px-5 rounded-lg text-xs font-semibold inline-flex items-center justify-center gap-2 shrink-0 cursor-pointer"
          >
            <span>Start Free Audit</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>
    </div>
  );
};
