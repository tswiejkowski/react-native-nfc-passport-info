import { NativeModules, Platform } from 'react-native';
import { getMRZKey } from './helpers';

const LINKING_ERROR =
  `The package 'react-native-read-nfc-passport' doesn't seem to be linked. Make sure: \n\n` +
  Platform.select({ ios: "- You have run 'pod install'\n", default: '' }) +
  '- You rebuilt the app after installing the package\n' +
  '- You are not using Expo Go\n';

const ReadNfcPassport = NativeModules.ReadNfcPassport
  ? NativeModules.ReadNfcPassport
  : new Proxy(
      {},
      {
        get() {
          throw new Error(LINKING_ERROR);
        },
      }
    );

const DATE_REGEX = /^\d{6}$/;

export function scanNfc({ documentNumber, dateOfBirth, dateOfExpiry }: any) {
  assert(
    typeof documentNumber === 'string',
    'expected string "documentNumber"'
  );
  assert(
    isDate(dateOfBirth),
    'expected string "dateOfBirth" in format "yyMMdd"'
  );
  assert(
    isDate(dateOfExpiry),
    'expected string "dateOfExpiry" in format "yyMMdd"'
  );

  return Platform?.OS === 'ios'
    ? scanNfcIos({ documentNumber, dateOfBirth, dateOfExpiry })
    : scanNfcAndroid({ documentNumber, dateOfBirth, dateOfExpiry });
}

async function scanNfcAndroid({
  documentNumber,
  dateOfBirth,
  dateOfExpiry,
  quality = 1,
}: any) {
  try {
    const res = await ReadNfcPassport?.scan({
      documentNumber,
      dateOfBirth,
      dateOfExpiry,
      quality,
    });
    return res;
  } catch (error) {
    cancelScanNfc();
    throw error;
  }
}

export function cancelScanNfc() {
  ReadNfcPassport?.cancel();
}

function scanNfcIos({ documentNumber, dateOfBirth, dateOfExpiry }: any) {
  const mrzKeyTemp = getMRZKey(documentNumber, dateOfBirth, dateOfExpiry);
  ReadNfcPassport?.readPassport?.(mrzKeyTemp, {})
    .then(async (msg: any) => {
      return msg;
    })
    .catch((err: any) => {
      throw err;
    });
}

function assert(statement: any, err: any) {
  if (!statement) {
    throw new Error(err || 'Assertion failed');
  }
}

function isDate(str: string) {
  return typeof str === 'string' && DATE_REGEX.test(str);
}
