import { APK_BLOG_POSTS, type BlogCategory, type BlogPost } from './blogPostsApk';
import { WEB_BLOG_POSTS } from './blogPostsWeb';

export type { BlogCategory, BlogPost };

export const BLOG_CATEGORIES: Array<'All' | BlogCategory> = [
  'All',
  'Android APK',
  'Web & API',
  'Cloud & BaaS',
  'Play Store Compliance',
];

export const BLOG_POSTS: BlogPost[] = [...APK_BLOG_POSTS, ...WEB_BLOG_POSTS].sort(
  (a, b) => new Date(b.publishedAt).getTime() - new Date(a.publishedAt).getTime()
);

export function getBlogPostBySlug(slug?: string | null): BlogPost | null {
  if (!slug) return null;
  const clean = slug.trim().toLowerCase().replace(/^\/+|\/+$/g, '');
  return BLOG_POSTS.find((p) => p.slug === clean) || null;
}
