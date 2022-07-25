// Next.js API route support: https://nextjs.org/docs/api-routes/introduction
import type {NextApiRequest, NextApiResponse} from 'next'
import * as jose from 'jose'
import {getPublicCompressed} from '@toruslabs/eccrypto'

type Data = {
  name: string
}

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse<Data>,
) {
  try {
    const idToken = req.headers.authorization?.split(' ')[1] || ''
    const app_scoped_privkey = req.body.privateKey
    const jwks = jose.createRemoteJWKSet(
      new URL('https://api.openlogin.com/jwks'),
    )
    const jwtDecoded = await jose.jwtVerify(idToken, jwks, {
      algorithms: ['ES256'],
    })

    const app_pub_key = getPublicCompressed(
      Buffer.from(app_scoped_privkey.padStart(64, '0'), 'hex'),
    ).toString('hex')
    console.log(app_pub_key)
    if ((jwtDecoded.payload as any).wallets[0].public_key == app_pub_key) {
      // Verified
      console.log('Validation Success')
      res.status(200).json({name: 'Validation Success'})
    } else {
      res.status(200).json({name: 'Validation'})
    }
  } catch (error) {
    res.status(500).json({error: error.message})
  }
}
