const select = require('xpath.js');
const crypto = require('crypto');

function findAttr(node, localName, namespace) {
  for (var i = 0; i<node.attributes.length; i++) {
    var attr = node.attributes[i]   

    if (attrEqualsExplicitly(attr, localName, namespace) || attrEqualsImplicitly(attr, localName, namespace, node)) {         
      return attr
    }
  }
  return null
}

function findFirst(doc, xpath) {  
  var nodes = select(doc, xpath)    
  if (nodes.length==0) throw "could not find xpath " + xpath
  return nodes[0]
}

function findChilds(node, localName, namespace) {
  node = node.documentElement || node;
  var res = []
  for (var i = 0; i<node.childNodes.length; i++) {
    var child = node.childNodes[i]       
    if (child.localName==localName && (child.namespaceURI==namespace || !namespace)) {
      res.push(child)
    }
  }
  return res
}

function attrEqualsExplicitly(attr, localName, namespace) {
  return attr.localName==localName && (attr.namespaceURI==namespace || !namespace)
}

function attrEqualsImplicitly(attr, localName, namespace, node) {
  return attr.localName==localName && ((!attr.namespaceURI && node.namespaceURI==namespace) || !namespace)
}

var xml_special_to_encoded_attribute = {
    '&': '&amp;',
    '<': '&lt;',
    '"': '&quot;',
    '\r': '&#xD;',
    '\n': '&#xA;',
    '\t': '&#x9;'
}

var xml_special_to_encoded_text = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '\r': '&#xD;'
}

function encodeSpecialCharactersInAttribute(attributeValue){
    return attributeValue
        .replace(/[\r\n\t ]+/g, ' ') // White space normalization (Note: this should normally be done by the xml parser) See: https://www.w3.org/TR/xml/#AVNormalize
        .replace(/([&<"\r\n\t])/g, function(str, item){
            // Special character normalization. See:
            // - https://www.w3.org/TR/xml-c14n#ProcessingModel (Attribute Nodes)
            // - https://www.w3.org/TR/xml-c14n#Example-Chars
            return xml_special_to_encoded_attribute[item]
        })
}

function encodeSpecialCharactersInText(text){
    return text
        .replace(/\r\n?/g, '\n')  // Line ending normalization (Note: this should normally be done by the xml parser). See: https://www.w3.org/TR/xml/#sec-line-ends
        .replace(/([&<>\r])/g, function(str, item){
            // Special character normalization. See:
            // - https://www.w3.org/TR/xml-c14n#ProcessingModel (Text Nodes)
            // - https://www.w3.org/TR/xml-c14n#Example-Chars
            return xml_special_to_encoded_text[item]
        })
}

function publicPemToKeyData(pem) {
    const cert = crypto.createPublicKey({key: pem});
    const b = cert.export({type:'spki', format:'der'});
    return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength);
}

function privatePemToKeyData(pem) {
    const cert = crypto.createPrivateKey({key: pem});
    const b = cert.export({type:'pkcs8', format:'der'});
    return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength);
}

function stringToArrayBuffer(str) {
    const buf = new ArrayBuffer(str.length);
    const bufView = new Uint8Array(buf);
    for (let i = 0, strLen = str.length; i < strLen; i++) {
        bufView[i] = str.charCodeAt(i);
    }
    return buf;
}

function base64ToArrayBuffer(str) {
    const bStr = atob(str);
    return stringToArrayBuffer(bStr);
}

exports.findAttr = findAttr
exports.findChilds = findChilds
exports.encodeSpecialCharactersInAttribute = encodeSpecialCharactersInAttribute
exports.encodeSpecialCharactersInText = encodeSpecialCharactersInText
exports.findFirst = findFirst
exports.stringToArrayBuffer = stringToArrayBuffer;
exports.privatePemToKeyData = privatePemToKeyData;
exports.publicPemToKeyData = publicPemToKeyData;
exports.base64ToArrayBuffer = base64ToArrayBuffer