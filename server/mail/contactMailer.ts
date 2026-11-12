import nodemailer from 'nodemailer';
import type { StoredContactInquiry } from '../auth/accountStore.ts';

export interface ContactMailResult {
  delivered: boolean;
  mode: 'gmail_smtp' | 'custom_smtp' | 'unconfigured' | 'failed';
  to: string;
  error?: string;
}

const DEFAULT_RECEIVER_EMAIL = 'checkmyapk.com@gmail.com';

function escapeHtml(raw: string): string {
  return raw
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function getContactReceiverEmail(): string {
  const configured = process.env.CONTACT_RECEIVER_EMAIL?.trim();
  return configured || DEFAULT_RECEIVER_EMAIL;
}

export async function dispatchContactEmail(
  inquiry: StoredContactInquiry
): Promise<ContactMailResult> {
  const to = getContactReceiverEmail();
  const gmailPass = process.env.GMAIL_APP_PASSWORD?.replace(/["'\s]+/g, '').trim();
  const gmailUser = (process.env.GMAIL_SMTP_USER || to).trim();

  const smtpHost = process.env.SMTP_HOST?.trim();
  const smtpUser = process.env.SMTP_USER?.trim();
  const smtpPass = process.env.SMTP_PASS?.trim();
  const smtpPort = Number(process.env.SMTP_PORT || 587);

  let transporter: nodemailer.Transporter | null = null;
  let mode: ContactMailResult['mode'] = 'unconfigured';
  let fromAddress = gmailUser;

  if (gmailPass) {
    mode = 'gmail_smtp';
    fromAddress = gmailUser;
    transporter = nodemailer.createTransport({
      service: 'gmail',
      connectionTimeout: 8000,
      greetingTimeout: 8000,
      socketTimeout: 10000,
      auth: {
        user: gmailUser,
        pass: gmailPass,
      },
    });
  } else if (smtpHost && smtpUser && smtpPass) {
    mode = 'custom_smtp';
    fromAddress = (process.env.SMTP_FROM || smtpUser).trim();
    transporter = nodemailer.createTransport({
      host: smtpHost,
      port: smtpPort,
      secure: smtpPort === 465,
      connectionTimeout: 8000,
      greetingTimeout: 8000,
      socketTimeout: 10000,
      auth: {
        user: smtpUser,
        pass: smtpPass,
      },
    });
  }

  if (!transporter) {
    return {
      delivered: false,
      mode: 'unconfigured',
      to,
      error: 'GMAIL_APP_PASSWORD is not configured in .env yet.',
    };
  }

  const safeName = escapeHtml(inquiry.name);
  const safeEmail = escapeHtml(inquiry.email);
  const safeTopic = escapeHtml(inquiry.topic).replace(/\n/g, '<br />');
  const safeId = escapeHtml(inquiry.id);

  try {
    await transporter.sendMail({
      from: `"CheckMyAPK Contact" <${fromAddress}>`,
      to,
      replyTo: `"${inquiry.name.replace(/["\r\n]/g, '')}" <${inquiry.email.replace(/[\r\n]/g, '')}>`,
      subject: `[CheckMyAPK Contact #${inquiry.id}] Message from ${inquiry.name}`,
      text: [
        `New Contact Us Message — CheckMyAPK.com`,
        `Reference ID: ${inquiry.id}`,
        `Received At: ${inquiry.receivedAt}`,
        `User Name: ${inquiry.name}`,
        `User Email: ${inquiry.email}`,
        inquiry.userId ? `Account ID: ${inquiry.userId}` : null,
        ``,
        `Topic / Message:`,
        inquiry.topic,
      ]
        .filter(Boolean)
        .join('\n'),
      html: `
        <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 600px; margin: 0 auto; padding: 24px; background: #0b101d; color: #e2e8f0; border-radius: 16px; border: 1px solid #1e293b;">
          <h2 style="margin: 0 0 8px; color: #38bdf8; font-size: 18px;">New Contact Us Message — CheckMyAPK.com</h2>
          <p style="margin: 0 0 18px; color: #94a3b8; font-size: 12px;">Reference: <strong>${safeId}</strong> • ${escapeHtml(inquiry.receivedAt)}</p>
          <table style="width: 100%; border-collapse: collapse; margin-bottom: 16px; font-size: 13px;">
            <tr>
              <td style="padding: 8px 12px; background: #111827; color: #94a3b8; width: 120px; border: 1px solid #1f2937;"><strong>Name</strong></td>
              <td style="padding: 8px 12px; background: #0f172a; color: #ffffff; border: 1px solid #1f2937;">${safeName}</td>
            </tr>
            <tr>
              <td style="padding: 8px 12px; background: #111827; color: #94a3b8; border: 1px solid #1f2937;"><strong>Email</strong></td>
              <td style="padding: 8px 12px; background: #0f172a; color: #38bdf8; border: 1px solid #1f2937;"><a href="mailto:${safeEmail}" style="color: #38bdf8;">${safeEmail}</a></td>
            </tr>
          </table>
          <div style="padding: 14px 16px; background: #0f172a; border: 1px solid #1f2937; border-radius: 10px; font-size: 13px; line-height: 1.6; color: #f1f5f9;">
            <div style="font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em; color: #94a3b8; margin-bottom: 6px;">Topic / Message</div>
            <div>${safeTopic}</div>
          </div>
          <p style="margin: 16px 0 0; font-size: 11px; color: #64748b;">Hit Reply in Gmail to respond directly to ${safeEmail}.</p>
        </div>
      `,
    });

    return { delivered: true, mode, to };
  } catch (err: any) {
    console.error('[CheckMyAPK Contact Mailer] SMTP send failed:', err?.message || err);
    return {
      delivered: false,
      mode: 'failed',
      to,
      error: err?.message || 'SMTP delivery failed.',
    };
  }
}
