from burp import IBurpExtender, IHttpListener
from java.io import PrintWriter
import base64, re


class proxyConfig:
	host = 'teste-localhost.com.br'
	protocol = 'http'
	port = 80
	authorization = 'Basic d2VicHJveHk6N2YmS0ZLKTMz'
	ignore = r'(mozilla\.com$|mozilla\.net$|mozilla\.org$|firefox\.com$|firefox\.net$|firefox\.org$|googleapis\.com$|google\.com$|google\.com\.br$)'
	endpoint = '/w.php?e=1'
	decodeHeaders = r'(^location$)'
	encodeHeaders = r'(^referer$|^origin$|^cookie$)'
	renameHeaders = r'(^p-server$|^p-date$|^p-x-powered-by$|^p-x-frame-options$|^p-x-xss-protection$|^p-connection$)'

class BurpExtender(IBurpExtender, IHttpListener):
	def	registerExtenderCallbacks(self, callbacks):
		self._helpers = callbacks.getHelpers()
		self._stdout = PrintWriter(callbacks.getStdout(), True)
		self._callbacks = callbacks
		callbacks.setExtensionName("WebProxys")
		callbacks.registerHttpListener(self)

	def _headersToDict(self, headers):
		h = {}
		for i in headers:
			i = str(i).split(':', 1)
			if len(i) != 2 or len(i[1]) < 1 or len(i[0]) < 1:
				continue
			h[i[0].lower()] = i[1][1:] if i[1].startswith(' ') else i[1]
		return h
	def _prepareResponseHeaders(self, headers):
		h = self._headersToDict(headers)
		headers = [headers[0]]
		renamedHeaders = []
		for i in h:
			if re.search(proxyConfig.decodeHeaders, i) and len(h[i]) > 0:
				try:
					h[i] = h[i].encode('utf-8')
				except:
					pass

				h[i] = base64.b64decode(h[i]).decode()
			if re.search(proxyConfig.renameHeaders, i):
				if i[2:] in renamedHeaders:
					continue
				renamedHeaders.append(i[2:])
				headers.append('{}: {}'.format(i[2:], h[i]))
			elif i not in renamedHeaders:
				headers.append('{}: {}'.format(i, h[i]))
		return headers

	def _prepareRequestHeaders(self, target, headers):
		h = self._headersToDict(headers[1:])

		if re.search(proxyConfig.ignore, h['host']):
			return False


		headers[0] = re.findall(r'(.*?) \/(.*?) HTT(.*)', str(headers[0]))

		if len(headers[0]) < 1 or len(headers[0][0]) != 3:
			return False

		headers = ['{} {} HTT{}'.format(headers[0][0][0], proxyConfig.endpoint, headers[0][0][2])]

		for i in h:
			if i == 'host':

				headers.append('Host: {}'.format(proxyConfig.host))
			elif i == 'x-target' or i == 'x-authorization':
				continue
			elif re.search(proxyConfig.encodeHeaders, i):
				headers.append('{}: {}'.format(i, base64.b64encode(h[i].encode()).decode()))
			else:
				headers.append('{}: {}'.format(i, h[i]))

		headers.append('X-Authorization: {}'.format(proxyConfig.authorization))
		headers.append('X-Target: {}'.format(target))
		return headers
		
	def _desbug(self, headers, body, name=''):
		self._stdout.println('------- {} ------'.format(name))
		for i in headers:
			self._stdout.println(i)

		self._stdout.println('\n{}'.format(body))
		self._stdout.println('--------------------------------')

	def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
		if toolFlag != self._callbacks.TOOL_PROXY:
			return

		if not messageIsRequest:
			responseInfo = self._helpers.analyzeResponse(messageInfo.getResponse())
			body = messageInfo.getResponse()[responseInfo.getBodyOffset():]
			headers = self._prepareResponseHeaders(list(responseInfo.getHeaders()))
			messageInfo.setResponse(self._helpers.buildHttpMessage(headers, body))
			return

		requestInfo = self._helpers.analyzeRequest(messageInfo)
		headers = self._prepareRequestHeaders(self._helpers.base64Encode(str(requestInfo.getUrl())), list(requestInfo.getHeaders()))
		if not headers:
			return

		body = str(self._helpers.bytesToString(messageInfo.getRequest()[requestInfo.getBodyOffset():]).encode('utf-8'))
		if len(body) > 0:
			body = self._helpers.base64Encode(body)

		self._desbug(headers, body, 'REQ {}'.format(str(requestInfo.getUrl())))
		messageInfo.setRequest(self._helpers.buildHttpMessage(headers, self._helpers.stringToBytes(body)))
		messageInfo.setHttpService(self._helpers.buildHttpService(proxyConfig.host, proxyConfig.port, proxyConfig.protocol))		
