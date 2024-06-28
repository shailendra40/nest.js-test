// export function generateOTP(): string {
//     return Math.floor(100000 + Math.random() * 900000).toString();
//   }
  

// // src/utils/otp.ts
// export function generateOTP(length: number = 6): string {
//   const characters = '0123456789';
//   let otp = '';
//   for (let i = 0; i < length; i++) {
//     otp += characters[Math.floor(Math.random() * characters.length)];
//   }
//   return otp;
// }


// utils/otp.ts
export function generateOTP(): string {
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  return otp;
}
