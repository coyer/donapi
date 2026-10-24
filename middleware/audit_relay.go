package middleware

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/service/audit"
	"github.com/QuantumNous/new-api/setting/operation_setting"

	"github.com/bytedance/gopkg/util/gopool"
	"github.com/gin-gonic/gin"
)

func AuditMiddleware() gin.HandlerFunc {
	auditLogger := audit.GetAuditLogger()

	return func(c *gin.Context) {
		if !auditLogger.IsEnabled() {
			c.Next()
			return
		}

		startTime := time.Now()
		requestID := c.GetString(common.RequestIdKey)

		var requestBody []byte
		var files []audit.AuditFile
		contentType := c.GetHeader("Content-Type")

		if strings.HasPrefix(contentType, "multipart/form-data") {
			requestBody, files = extractMultipartData(c)
		} else if c.Request.Body != nil {
			bodyBytes, err := io.ReadAll(c.Request.Body)
			if err == nil {
				requestBody = bodyBytes
				c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

				files = extractEmbeddedFiles(bodyBytes)

				if len(files) == 0 && strings.Contains(strings.ToLower(contentType), "json") {
					common.SysLog(fmt.Sprintf("audit: no embedded files found in JSON request, content-type: %s, body length: %d", contentType, len(bodyBytes)))
				}
			} else {
				common.SysError(fmt.Sprintf("audit: failed to read request body: %v", err))
			}
		}

		blw := &bodyLogWriter{body: bytes.NewBufferString(""), ResponseWriter: c.Writer}
		c.Writer = blw

		c.Next()

		if c.Writer.Status() >= 400 {
			return
		}

		tokenKey := common.GetContextKeyString(c, constant.ContextKeyTokenKey)
		if tokenKey == "" {
			username := c.GetString("username")
			if username != "" {
				tokenKey = fmt.Sprintf("user-%s", username)
			} else {
				tokenKey = "anonymous"
			}
		}

		record := &audit.AuditRecord{
			RequestID:   requestID,
			Timestamp:   startTime,
			TokenKey:    maskTokenKey(tokenKey),
			TokenID:     common.GetContextKeyInt(c, constant.ContextKeyTokenId),
			UserID:      common.GetContextKeyInt(c, constant.ContextKeyUserId),
			UserEmail:   common.GetContextKeyString(c, constant.ContextKeyUserEmail),
			Model:       c.GetString("original_model"),
			RelayMode:   c.GetInt("relay_mode"),
			RelayFormat: getRelayFormatFromPath(c.Request.URL.Path),
			RequestBody: json.RawMessage(requestBody),
			Files:       files,
			Metadata: map[string]interface{}{
				"client_ip":      c.ClientIP(),
				"user_agent":     c.GetHeader("User-Agent"),
				"request_method": c.Request.Method,
				"request_path":   c.Request.URL.Path,
				"status_code":    c.Writer.Status(),
				"latency_ms":     time.Since(startTime).Milliseconds(),
				"channel_id":     common.GetContextKeyInt(c, constant.ContextKeyChannelId),
				"channel_type":   common.GetContextKeyInt(c, constant.ContextKeyChannelType),
				"channel_name":   common.GetContextKeyString(c, constant.ContextKeyChannelName),
			},
		}

		gopool.Go(func() {
			auditLogger.Log(record)
		})
	}
}

type bodyLogWriter struct {
	gin.ResponseWriter
	body *bytes.Buffer
}

func (w bodyLogWriter) Write(b []byte) (int, error) {
	w.body.Write(b)
	return w.ResponseWriter.Write(b)
}

func extractMultipartData(c *gin.Context) ([]byte, []audit.AuditFile) {
	var requestBody map[string]interface{} = make(map[string]interface{})
	var files []audit.AuditFile

	err := c.Request.ParseMultipartForm(32 << 20)
	if err != nil {
		return nil, nil
	}

	if c.Request.MultipartForm != nil {
		for key, values := range c.Request.MultipartForm.Value {
			if len(values) == 1 {
				requestBody[key] = values[0]
			} else {
				requestBody[key] = values
			}
		}

		setting := operation_setting.GetAuditSetting()
		maxFileSizeBytes := setting.MaxFileSize * 1024 * 1024
		for key, fileHeaders := range c.Request.MultipartForm.File {
			for _, fh := range fileHeaders {
				file, err := fh.Open()
				if err != nil {
					continue
				}
				data, err := io.ReadAll(file)
				file.Close()
				if err != nil {
					continue
				}

				if int64(len(data)) > maxFileSizeBytes {
					continue
				}

				files = append(files, audit.AuditFile{
					Filename:    fh.Filename,
					ContentType: fh.Header.Get("Content-Type"),
					Size:        int64(len(data)),
					Base64Data:  base64.StdEncoding.EncodeToString(data),
				})

				_ = key
			}
		}
	}

	if model := c.PostForm("model"); model != "" {
		requestBody["model"] = model
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return nil, files
	}
	return jsonData, files
}

func maskTokenKey(key string) string {
	if key == "" || key == "anonymous" {
		return "anonymous"
	}
	if strings.HasPrefix(key, "user-") {
		return key
	}
	if len(key) <= 8 {
		return "unknown"
	}
	return key[:4] + "_xxxx_" + key[len(key)-4:]
}

func getRelayFormatFromPath(path string) string {
	switch {
	case strings.HasPrefix(path, "/v1/messages"):
		return "claude"
	case strings.HasPrefix(path, "/v1beta/"):
		return "gemini"
	case strings.HasPrefix(path, "/v1/responses"):
		return "openai_responses"
	case strings.HasPrefix(path, "/v1/embeddings"):
		return "embedding"
	case strings.HasPrefix(path, "/v1/audio"):
		return "openai_audio"
	case strings.HasPrefix(path, "/v1/images"):
		return "openai_image"
	case strings.HasPrefix(path, "/v1/rerank"):
		return "rerank"
	case strings.HasPrefix(path, "/mj/"):
		return "mj_proxy"
	case strings.HasPrefix(path, "/suno/"):
		return "task"
	default:
		return "openai"
	}
}

func extractEmbeddedFiles(bodyBytes []byte) []audit.AuditFile {
	files := make([]audit.AuditFile, 0)

	var req map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &req); err != nil {
		common.SysError(fmt.Sprintf("audit: failed to unmarshal JSON for file extraction: %v, body preview: %s", err, string(bodyBytes[:min(len(bodyBytes), 200)])))
		return files
	}

	messages, ok := req["messages"].([]interface{})
	if !ok {
		if _, hasMessages := req["messages"]; !hasMessages {
			common.SysLog("audit: no 'messages' field in JSON request")
		} else {
			common.SysError("audit: 'messages' field is not an array")
		}
		return files
	}

	for msgIdx, msg := range messages {
		msgMap, ok := msg.(map[string]interface{})
		if !ok {
			continue
		}

		content, ok := msgMap["content"]
		if !ok {
			continue
		}

		switch c := content.(type) {
		case string:
			continue
		case []interface{}:
			for itemIdx, item := range c {
				itemMap, ok := item.(map[string]interface{})
				if !ok {
					continue
				}

				itemType, ok := itemMap["type"].(string)
				if !ok {
					continue
				}

				switch itemType {
				case "image_url":
					files = append(files, extractImageFile(itemMap, msgIdx, itemIdx)...)
				case "file":
					files = append(files, extractGenericFile(itemMap, msgIdx, itemIdx)...)
				}
			}
		}
	}

	if len(files) > 0 {
		common.SysLog(fmt.Sprintf("audit: extracted %d embedded files from request", len(files)))
	}

	return files
}

func extractImageFile(itemMap map[string]interface{}, msgIdx, itemIdx int) []audit.AuditFile {
	files := make([]audit.AuditFile, 0)

	imageURL, ok := itemMap["image_url"].(map[string]interface{})
	if !ok {
		common.SysError(fmt.Sprintf("audit: invalid image_url at message[%d].content[%d]", msgIdx, itemIdx))
		return files
	}

	url, ok := imageURL["url"].(string)
	if !ok {
		common.SysError(fmt.Sprintf("audit: image_url.url is not a string at message[%d].content[%d]", msgIdx, itemIdx))
		return files
	}

	if !strings.HasPrefix(url, "data:") {
		common.SysLog(fmt.Sprintf("audit: image URL is not base64 data URI at message[%d].content[%d]: %s", msgIdx, itemIdx, url[:min(len(url), 50)]))
		return files
	}

	parts := strings.SplitN(url, ",", 2)
	if len(parts) != 2 {
		common.SysError(fmt.Sprintf("audit: invalid data URL format at message[%d].content[%d]: %s", msgIdx, itemIdx, url[:min(len(url), 100)]))
		return files
	}

	mimePart := parts[0]
	base64Data := parts[1]
	if !strings.HasSuffix(mimePart, ";base64") {
		common.SysError(fmt.Sprintf("audit: missing base64 suffix in mime type at message[%d].content[%d]: %s", msgIdx, itemIdx, mimePart))
		return files
	}

	mimeType := strings.TrimSuffix(mimePart, ";base64")

	decoded, err := base64.StdEncoding.DecodeString(base64Data)
	if err != nil {
		common.SysError(fmt.Sprintf("audit: failed to decode base64 image at message[%d].content[%d]: %v, data length: %d", msgIdx, itemIdx, err, len(base64Data)))
		return files
	}

	filename := detectFilenameFromMime(mimeType, msgIdx, itemIdx)

	files = append(files, audit.AuditFile{
		Filename:    filename,
		ContentType: mimeType,
		Size:        int64(len(decoded)),
		Base64Data:  base64.StdEncoding.EncodeToString(decoded),
	})

	common.SysLog(fmt.Sprintf("audit: successfully extracted embedded image at message[%d].content[%d], size: %d bytes, type: %s, filename: %s", msgIdx, itemIdx, len(decoded), mimeType, filename))

	return files
}

func extractGenericFile(itemMap map[string]interface{}, msgIdx, itemIdx int) []audit.AuditFile {
	files := make([]audit.AuditFile, 0)

	fileObj, ok := itemMap["file"].(map[string]interface{})
	if !ok {
		common.SysError(fmt.Sprintf("audit: invalid file object at message[%d].content[%d]", msgIdx, itemIdx))
		return files
	}

	fileData, ok := fileObj["file_data"].(string)
	if !ok {
		common.SysError(fmt.Sprintf("audit: missing file_data at message[%d].content[%d]", msgIdx, itemIdx))
		return files
	}

	mimeType, _ := fileObj["mime_type"].(string)
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}

	filename, _ := fileObj["filename"].(string)
	if filename == "" {
		filename = detectFilenameFromMime(mimeType, msgIdx, itemIdx)
	}

	decoded, err := base64.StdEncoding.DecodeString(fileData)
	if err != nil {
		common.SysError(fmt.Sprintf("audit: failed to decode base64 file at message[%d].content[%d]: %v, data length: %d", msgIdx, itemIdx, err, len(fileData)))
		return files
	}

	files = append(files, audit.AuditFile{
		Filename:    filename,
		ContentType: mimeType,
		Size:        int64(len(decoded)),
		Base64Data:  base64.StdEncoding.EncodeToString(decoded),
	})

	common.SysLog(fmt.Sprintf("audit: successfully extracted embedded file at message[%d].content[%d], size: %d bytes, type: %s, filename: %s", msgIdx, itemIdx, len(decoded), mimeType, filename))

	return files
}

func detectFilenameFromMime(mimeType string, msgIdx, itemIdx int) string {
	ext := ".bin"

	switch mimeType {
	case "image/png":
		ext = ".png"
	case "image/jpeg", "image/jpg":
		ext = ".jpg"
	case "image/gif":
		ext = ".gif"
	case "image/webp":
		ext = ".webp"
	case "image/svg+xml":
		ext = ".svg"
	case "application/pdf":
		ext = ".pdf"
	case "application/msword":
		ext = ".doc"
	case "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
		ext = ".docx"
	case "application/vnd.ms-excel":
		ext = ".xls"
	case "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":
		ext = ".xlsx"
	case "application/vnd.ms-powerpoint":
		ext = ".ppt"
	case "application/vnd.openxmlformats-officedocument.presentationml.presentation":
		ext = ".pptx"
	case "application/zip":
		ext = ".zip"
	case "application/gzip":
		ext = ".gz"
	case "application/x-tar":
		ext = ".tar"
	case "application/x-7z-compressed":
		ext = ".7z"
	case "application/x-rar-compressed":
		ext = ".rar"
	case "text/plain":
		ext = ".txt"
	case "text/csv":
		ext = ".csv"
	case "text/html":
		ext = ".html"
	case "text/css":
		ext = ".css"
	case "text/markdown":
		ext = ".md"
	case "application/json":
		ext = ".json"
	case "application/xml", "text/xml":
		ext = ".xml"
	case "application/yaml", "text/yaml":
		ext = ".yaml"
	case "text/toml":
		ext = ".toml"
	case "text/x-c":
		ext = ".c"
	case "text/x-csrc":
		ext = ".c"
	case "text/x-c++":
		ext = ".cpp"
	case "text/x-c++src":
		ext = ".cpp"
	case "text/x-chdr":
		ext = ".h"
	case "text/x-c++hdr":
		ext = ".hpp"
	case "text/x-python":
		ext = ".py"
	case "text/x-python-script":
		ext = ".py"
	case "application/javascript", "text/javascript":
		ext = ".js"
	case "application/typescript", "text/typescript":
		ext = ".ts"
	case "application/ecmascript":
		ext = ".es"
	case "text/x-java":
		ext = ".java"
	case "text/x-java-source":
		ext = ".java"
	case "text/x-go":
		ext = ".go"
	case "text/x-rust":
		ext = ".rs"
	case "text/x-ruby":
		ext = ".rb"
	case "application/x-php", "text/x-php":
		ext = ".php"
	case "text/x-swift":
		ext = ".swift"
	case "text/x-kotlin":
		ext = ".kt"
	case "text/x-scala":
		ext = ".scala"
	case "text/x-csharp":
		ext = ".cs"
	case "text/x-lua":
		ext = ".lua"
	case "text/x-perl":
		ext = ".pl"
	case "text/x-shellscript", "application/x-sh":
		ext = ".sh"
	case "application/x-powershell":
		ext = ".ps1"
	case "text/x-makefile":
		ext = ".mk"
	case "text/x-dockerfile":
		ext = ".Dockerfile"
	case "application/sql":
		ext = ".sql"
	case "application/octet-stream":
		ext = ".bin"
	}

	return fmt.Sprintf("embedded_file_%d_%d%s", msgIdx, itemIdx, ext)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
