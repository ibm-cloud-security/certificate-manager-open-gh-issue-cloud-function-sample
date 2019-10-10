const { promisify } = require('bluebird');
const request = promisify(require('request'));
const jwtVerify = promisify(require('jsonwebtoken').verify);

async function getPublicKey() {
    const keysOptions = {
        method: 'GET',
        url: `https://<region>.certificate-manager.cloud.ibm.com/api/v1/instances/<Encoded Instance CRN>/notifications/publicKey?keyFormat=pem`,
        headers: {
            'cache-control': 'no-cache'
        }
    };
    const keysResponse = await request(keysOptions);
    return JSON.parse(keysResponse.body).publicKey;
}

function getDate(timestamp) {
    return new Date(timestamp).toDateString();
}

function createIssueBody(notificationData) {
    if (notificationData.event_type === "cert_about_to_expire_reimport_required" ||
        notificationData.event_type === "cert_about_to_expire_renew_required")
        return `The following ${notificationData.certificates.length} certificate/s will expire on ${getDate(notificationData.expiry_date)}:
${notificationData.certificates.reduce((accumulator, currentValue) => {
            return accumulator + `
> Domain(s): ${currentValue.domains}
CRN: ${currentValue.cert_crn}
`;
        }, "")}`;
    if (notificationData.event_type === "cert_expired_reimport_required" ||
        notificationData.event_type === "cert_expired_renew_required")
        return `The following ${notificationData.certificates.length} certificate/s have already expired:
${notificationData.certificates.reduce((accumulator, currentValue) => {
            return accumulator + `
> Domain(s): ${currentValue.domains}
CRN: ${currentValue.cert_crn}
`;
        }, "")}`;
}

async function main(params) {
    try {
        const publicKey = await getPublicKey();
        const decodedNotification = await jwtVerify(params.data, publicKey);
        console.log(`Notification: ${JSON.stringify(decodedNotification)}`);
        const body = createIssueBody(decodedNotification);
        if (!body) {
            console.log(`No action needed for this notification. Event type: ${decodedNotification.event_type}`);
            return;
        }
        const options = {
            method: 'POST',
            url: 'https://api.github.ibm.com/repos/<Repo Owner>/<Repo Name>/issues',
            headers:
            {
                'cache-control': 'no-cache',
                'content-type': 'application/json',
                'authorization': 'Token <PAT>'
            },
            json:
            {
                title: "Certificates about to expire/already expired",
                body: body,
                labels: ['certificates', 'security'],
                assignees: ['<usernames>']
            }
        };
        // Make POST request
        await request(options);

    } catch (err) {
        console.log(err);
    }
}
