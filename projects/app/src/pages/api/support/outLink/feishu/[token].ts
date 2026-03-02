import type { NextApiRequest, NextApiResponse } from 'next';
import { authOutLinkValid } from '@fastgpt/service/support/permission/publish/authLink';
import { getLogger, LogCategories } from '@fastgpt/service/common/logger';
import { jsonRes } from '@fastgpt/service/common/response';

type FeishuEvent = {
  type?: string;
  challenge?: string;
  token?: string;
  header?: {
    event_id?: string;
    event_type?: string;
    create_time?: string;
    tenant_key?: string;
  };
  event?: {
    message?: {
      message_id: string;
      chat_id: string;
      chat_type: 'p2p' | 'group';
      message_type: string;
      content: string; // JSON string
    };
    sender?: {
      sender_type?: string;
      sender_id?: {
        open_id?: string;
        union_id?: string;
        user_id?: string;
      };
    };
  };
};

const logger = getLogger(LogCategories.MODULE.OUTLINK.FEISHU ?? LogCategories.SYSTEM);

// simple in-memory session cache: `${shareId}|${chatKey}` -> chatId
const chatSessionCache = new Map<string, string>();
// token cache per appId
const tenantTokenCache = new Map<string, { token: string; expiredAt: number }>();
// simple event de-dup (event_id -> timestamp)
const eventDedupCache = new Map<string, number>();
const EVENT_DEDUP_TTL = 5 * 60 * 1000;
// user name cache: open_id -> name
const userNameCache = new Map<string, { name: string; expiredAt: number }>();

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const { token: shareId } = req.query as { token: string };
  const body = req.body as FeishuEvent;

  try {
    // 1) URL 验证
    if (body.type === 'url_verification' && body.challenge) {
      return res.status(200).json({ challenge: body.challenge });
    }

    // 2) 校验 shareId 是否存在，并拿到飞书配置
    const { outLinkConfig } = await authOutLinkValid({ shareId });
    const feishuConfig = outLinkConfig?.app as {
      appId?: string;
      appSecret?: string;
      encryptKey?: string;
      verificationToken?: string;
    };

    // 3) 验证飞书 token（可选），优先用 UI 配置
    const verifyToken = feishuConfig?.verificationToken || process.env.FEISHU_VERIFICATION_TOKEN;
    if (verifyToken && body.token && verifyToken !== body.token) {
      return res.status(403).json({ code: 403, msg: 'invalid feishu token' });
    }

    // 4) 只处理消息事件（忽略机器人自己发的消息）
    const message = body.event?.message;
    if (!message || message.message_type !== 'text') {
      return res.status(200).json({ code: 0 });
    }
    const senderType = body.event?.sender?.sender_type;
    if (senderType && senderType !== 'user') {
      return res.status(200).json({ code: 0 });
    }

    const contentObj = safeJson(message.content);
    const text = (contentObj.text || '').trim();
    if (!text) return res.status(200).json({ code: 0 });
    // group chat: only respond when @bot
    if (message.chat_type === 'group') {
      const mentions = contentObj.mentions || (message as any).mentions;
      if (!Array.isArray(mentions) || mentions.length === 0) {
        return res.status(200).json({ code: 0 });
      }
    }
    // 5) 幂等去重
    const eventId = body.header?.event_id;
    const dedupKey = eventId || `message:${message.message_id}`;
    if (dedupKey) {
      const ts = eventDedupCache.get(dedupKey);
      if (ts && Date.now() - ts < EVENT_DEDUP_TTL) {
        return res.status(200).json({ code: 0 });
      }
      eventDedupCache.set(dedupKey, Date.now());
      setTimeout(() => eventDedupCache.delete(dedupKey), EVENT_DEDUP_TTL).unref?.();
    }

    const senderId =
      body.event?.sender?.sender_id?.open_id || body.event?.sender?.sender_id?.user_id || 'unknown';
    const chatKey = `${message.chat_type}:${message.chat_id}:${senderId}`;
    const cacheKey = `${shareId}|${chatKey}`;
    const outLinkUid = chatKey;
    const chatId = chatSessionCache.get(cacheKey);

    // reset command: "/reset" (case-insensitive)
    if (/^\s*\/reset\s*$/i.test(text)) {
      chatSessionCache.delete(cacheKey);
      const tenantToken = await getTenantToken(feishuConfig);
      await replyFeishuMessage({
        tenantToken,
        messageId: message.message_id,
        text: '对话已重置，可以开始新对话了。'
      });
      return res.status(200).json({ code: 0 });
    }

    // 6) 先快速响应飞书，避免重试
    if (!res.headersSent) {
      res.status(200).json({ code: 0 });
    }

    // 7) 异步处理（占位 + 最终回复）
    (async () => {
      try {
        const tenantToken = await getTenantToken(feishuConfig);
        const userName = await getUserName(tenantToken, senderId);
        const timeStr = new Date().toISOString();
        await replyFeishuCard({
          tenantToken,
          messageId: message.message_id,
          title: '处理中',
          md: '小助手已经收到啦 正在处理中...'
        });

        const baseUrl = getBaseUrl(req);
        const resp = await fetch(`${baseUrl}/api/v1/chat/completions`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            shareId,
            outLinkUid,
            chatId,
            messages: [
              {
                role: 'user',
                content: `(来自用户: ${userName}; 时间: ${timeStr}) ${text}`
              }
            ],
            stream: false,
            detail: false,
            retainDatasetCite: false,
            variables: {}
          })
        });

        const data = await resp.json();
        if (data?.id) {
          chatSessionCache.set(cacheKey, data.id as string);
        }

        const answer =
          data?.choices?.[0]?.message?.content || data?.choices?.[0]?.message || 'No response.';

        await replyFeishuCard({
          tenantToken,
          messageId: message.message_id,
          title: '回复',
          md: String(answer)
        });
      } catch (error) {
        logger.error('Feishu async handler failed', { error });
      }
    })();

    return;
  } catch (error: any) {
    logger.error('Feishu webhook failed', { error });
    return jsonRes(res, { code: 500, error: error?.message || 'feishu webhook error' });
  }
}

function safeJson(str: string): any {
  try {
    return JSON.parse(str);
  } catch (error) {
    return {};
  }
}

function getBaseUrl(req: NextApiRequest) {
  const proto = (req.headers['x-forwarded-proto'] as string) || 'http';
  const host = req.headers.host;
  return `${proto}://${host}`;
}

async function getTenantToken(feishuConfig?: {
  appId?: string;
  appSecret?: string;
}): Promise<string> {
  const appId = feishuConfig?.appId;
  const appSecret = feishuConfig?.appSecret;
  if (!appId || !appSecret) {
    throw new Error('Feishu appId/appSecret is missing in publish config');
  }

  const now = Date.now();
  const cached = tenantTokenCache.get(appId);
  if (cached && cached.expiredAt > now + 60_000) {
    return cached.token;
  }

  const resp = await fetch(
    'https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal',
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ app_id: appId, app_secret: appSecret })
    }
  );
  const data = (await resp.json()) as {
    code: number;
    tenant_access_token?: string;
    expire?: number;
  };
  if (data.code !== 0 || !data.tenant_access_token) {
    throw new Error(`feishu token error: ${JSON.stringify(data)}`);
  }

  tenantTokenCache.set(appId, {
    token: data.tenant_access_token,
    expiredAt: now + (data.expire || 5400) * 1000
  });
  return tenantTokenCache.get(appId)!.token;
}

async function replyFeishuMessage({
  tenantToken,
  messageId,
  text
}: {
  tenantToken: string;
  messageId: string;
  text: string;
}) {
  const url = `https://open.feishu.cn/open-apis/im/v1/messages/${messageId}/reply`;
  const resp = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${tenantToken}`
    },
    body: JSON.stringify({
      msg_type: 'text',
      content: JSON.stringify({ text })
    })
  });

  const data = await resp.json();
  if (data.code !== 0) {
    logger.error('Feishu reply failed', { data });
  }
}

async function replyFeishuCard({
  tenantToken,
  messageId,
  title,
  md
}: {
  tenantToken: string;
  messageId: string;
  title: string;
  md: string;
}) {
  const url = `https://open.feishu.cn/open-apis/im/v1/messages/${messageId}/reply`;
  const resp = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${tenantToken}`
    },
    body: JSON.stringify({
      msg_type: 'interactive',
      content: JSON.stringify(buildMarkdownCard(title, md))
    })
  });

  const data = await resp.json();
  if (data.code !== 0) {
    logger.error('Feishu reply card failed', { data });
  }
}

function buildMarkdownCard(title: string, md: string) {
  return {
    config: { wide_screen_mode: true },
    header: {
      title: {
        tag: 'plain_text',
        content: title
      }
    },
    elements: [
      {
        tag: 'markdown',
        content: md || ' '
      }
    ]
  };
}

async function getUserName(tenantToken: string, openId: string) {
  if (!openId || openId === 'unknown') return 'unknown';
  const now = Date.now();
  const cached = userNameCache.get(openId);
  if (cached && cached.expiredAt > now + 60_000) {
    return cached.name;
  }

  const url = `https://open.feishu.cn/open-apis/contact/v3/users/${openId}?user_id_type=open_id`;
  const resp = await fetch(url, {
    method: 'GET',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${tenantToken}`
    }
  });
  const data = await resp.json();
  const name = data?.data?.user?.name || data?.data?.user?.display_name || 'unknown';
  userNameCache.set(openId, { name, expiredAt: now + 60 * 60 * 1000 });
  return name;
}

export const config = {
  api: {
    bodyParser: true
  }
};
