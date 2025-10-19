import * as fs from 'fs';
import logger from '../logger';
import config from '../config';

const CHUNK_SIZE = 1024;
const MAX_WINDOW_SIZE = 50 * CHUNK_SIZE;
const MAX_ITERATIONS = 100;

function extractDateFromLogLine(line: string): number | undefined {
  // Extract time from log: "2021-08-31T12:34:56Z" or "2021-08-31T12:34:56.123456Z"
  const dateMatch = line.match(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{6})?Z/);
  if (!dateMatch) {
    return undefined;
  }

  const dateStr = dateMatch[0];
  const date = new Date(dateStr);
  const timestamp = Math.floor(date.getTime() / 1000); // Remove decimal (microseconds are added later)

  const timePart = dateStr.split('T')[1];
  const microseconds = timePart.split('.')[1] || '';

  if (!microseconds) {
    return timestamp;
  }

  return parseFloat(timestamp + '.' + microseconds);
}

function readLineAt(fd: number, startPos: number): { line: string; nextPos: number } | null {
  const stat = fs.fstatSync(fd);
  if (startPos >= stat.size) {
    return null;
  }

  // Set startPos at the next newline
  const headBuf = Buffer.allocUnsafe(Math.min(CHUNK_SIZE, stat.size - startPos));
  const headRead = fs.readSync(fd, headBuf, 0, headBuf.length, startPos);
  if (headRead <= 0) {
    return null;
  }
  const nl = headBuf.indexOf(0x0a); // '\n'
  if (nl !== -1 && startPos !== 0) {
    startPos = startPos + nl + 1;
  }

  let pos = startPos;
  let chunks: Buffer[] = [];
  while (pos < stat.size) {
    const toRead = Math.min(CHUNK_SIZE, stat.size - pos);
    const buf = Buffer.allocUnsafe(toRead);
    const n = fs.readSync(fd, buf, 0, toRead, pos);
    if (n <= 0) {
      break;
    }
    const slice = buf.subarray(0, n);
    const idx = slice.indexOf(0x0a);
    if (idx !== -1) {
      chunks.push(slice.subarray(0, idx));
      const line = Buffer.concat(chunks).toString('utf8');
      const nextPos = pos + idx + 1;
      return { line, nextPos };
    } else {
      chunks.push(slice);
      pos += n;
    }
  }
  if (chunks.length === 0) {
    return null;
  }
  const line = Buffer.concat(chunks).toString('utf8');
  return { line, nextPos: stat.size };
}

function findWindowInLogs(filePath: string, targetTimestamp: number): number {
  const fd = fs.openSync(filePath, 'r');
  try {
    const size = fs.fstatSync(fd).size;
    let low = 0;
    let high = size - MAX_WINDOW_SIZE;
    let iterations = 0;

    while (low < high && iterations < MAX_ITERATIONS) {
      iterations++;
      const mid = Math.floor((low + high) / 2);

      let record = readLineAt(fd, mid);
      if (!record) {
        throw new Error(`Failed to read log line during binary search`);
      }

      let ts = extractDateFromLogLine(record.line);

      if (ts === undefined) { // usually caused by empty lines between Core restarts, just jump a few bytes forward
        record = readLineAt(fd, record.nextPos + 10);
        if (!record) {
          break;
        }
        ts = extractDateFromLogLine(record.line);
        if (ts === undefined) {
          break;
        }
      }

      if (ts < targetTimestamp) {
        low = record.nextPos;
      } else {
        high = mid;
      }
    }

    return Math.min(low, size);
  } finally {
    fs.closeSync(fd);
  }
}

function scanWindowForFirstSeen(filePath: string, startOffset: number, endTimestamp: number, hash: string): number | undefined {
  const fd = fs.openSync(filePath, 'r');
  try {
    const stat = fs.fstatSync(fd);
    let pos = startOffset;
    let logTimestamp: number | undefined = undefined;

    const needles = [
      `Saw new header hash=${hash}`,
      `Saw new cmpctblock header hash=${hash}`,
      `Initialized PartiallyDownloadedBlock for block ${hash}`,
      `UpdateTip: new best=${hash}`,
    ];

    const maxPos = Math.min(stat.size, startOffset + MAX_WINDOW_SIZE);
    while (pos < maxPos) {
      const record = readLineAt(fd, pos);
      if (!record) {
        break;
      }
      const { line, nextPos } = record;
      pos = nextPos;

      logTimestamp = extractDateFromLogLine(line);
      if (logTimestamp === undefined) {
        continue;
      }
      if (logTimestamp > endTimestamp) {
        break;
      }

      for (const n of needles) {
        if (line.includes(n)) {
          return logTimestamp;
        }
      }
    }

    return undefined;
  } finally {
    fs.closeSync(fd);
  }
}

export function scanLastLinesForFirstSeen(filePath: string, hash: string, blockTimestamp: number): number | undefined {
  const fd = fs.openSync(filePath, 'r');
  try {
    const stat = fs.fstatSync(fd);
    const buf = Buffer.allocUnsafe(CHUNK_SIZE);
    const minPos = stat.size > MAX_WINDOW_SIZE ? stat.size - MAX_WINDOW_SIZE : 0;

    let pos = stat.size;
    let carry = '';

    const cutoff = blockTimestamp - 7200; // block time can be up to 2 hours in the future
    const headerNeedle = `Saw new header hash=${hash}`;
    const cmpctNeedle = `Saw new cmpctblock header hash=${hash}`;
    const partNeedle = `Initialized PartiallyDownloadedBlock for block ${hash}`;
    const updateNeedle = `UpdateTip: new best=${hash}`;

    let bestMatch: number | undefined = undefined;
    while (pos > minPos) {
      const nextPos = Math.max(minPos, pos - buf.length);
      const toRead = pos - nextPos;
      pos = nextPos;

      const bytesRead = fs.readSync(fd, buf, 0, toRead, pos);
      if (bytesRead <= 0) {
        break;
      }

      const data = buf.toString('utf8', 0, bytesRead) + carry;
      const lines = data.split('\n');
      carry = lines.shift() ?? '';

      for (let i = lines.length - 1; i >= 0; i--) {
        const line = lines[i];
        const ts = extractDateFromLogLine(line);
        if (!ts) {
          continue;
        }

        if (line.includes(headerNeedle) || line.includes(cmpctNeedle)) {
          return ts;
        }

        if (line.includes(partNeedle) || line.includes(updateNeedle)) {
          bestMatch = ts;
        }

        if (ts < cutoff) {
          pos = minPos; // force outer loop to end
          break;
        }
      }
    }
    return bestMatch;
  } finally {
    fs.closeSync(fd);
  }
}

export function getBlockFirstSeenFromLogs(hash: string, blockTimestamp: number, oldestLogTimestamp: number): number | undefined {
  const debugLogPath = config.CORE_RPC.DEBUG_LOG_PATH;
  if (!debugLogPath) {
    return undefined;
  }

  if (blockTimestamp + 3600 > (Date.now() / 1000)) { // Recent block: search the end of the log for recent blocks
    try {
      return scanLastLinesForFirstSeen(debugLogPath, hash, blockTimestamp);
    } catch (e) {
      logger.debug(`Cannot parse recent block first seen time from Core logs. Reason: ${e instanceof Error ? e.message : e}`);
      return undefined;
    }
  }

  // Older block but still within log range: do a binary search to find the right window
  if (blockTimestamp + 7200 > oldestLogTimestamp) {
    try {
      const startWindow = blockTimestamp - 7200; // block time can be up to 2 hours in the future
      const endWindow = blockTimestamp + 3600; // block time can be up to 1 hour in the past (approximating median past time)
      const startOffset = findWindowInLogs(debugLogPath, startWindow);
      return scanWindowForFirstSeen(debugLogPath, startOffset, endWindow, hash);
    } catch (e) {
      logger.debug(`Cannot parse block first seen time from Core logs. Reason: ${e instanceof Error ? e.message : e}`);
      return undefined;
    }
  }

  return undefined;
}

export function getOldestLogTimestampFromLogs(filePath: string): number | undefined {
  const fd = fs.openSync(filePath, 'r');
  try {
    const stat = fs.fstatSync(fd);
    if (stat.size === 0) {
      return undefined;
    }

    let pos = 0;
    for (let i = 0; i < 10 && pos < stat.size; i++) {
      const record = readLineAt(fd, pos);
      if (!record) {
        break;
      }
      const ts = extractDateFromLogLine(record.line);
      if (ts !== undefined) {
        return ts;
      }
      pos = record.nextPos;
    }
    return undefined;
  } finally {
    fs.closeSync(fd);
  }
}