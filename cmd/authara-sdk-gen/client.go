package main

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
)

func (g generator) clientFile() ([]byte, error) {
	ops, err := g.operations()
	if err != nil {
		return nil, err
	}
	methods := make([]string, 0, len(ops))
	for _, op := range ops {
		method, err := g.method(op)
		if err != nil {
			return nil, fmt.Errorf("operation %s %s (%s): %w", op.Method, op.Path, op.OperationID, err)
		}
		methods = append(methods, method)
	}

	var b bytes.Buffer
	b.WriteString(g.header())
	b.WriteString(g.clientImports(ops))
	b.WriteString(`func apiRequestOptions(incoming *http.Request, cookies []string, csrf bool) []requestOption {
	var opts []requestOption
	if len(cookies) > 0 {
		opts = append(opts, func(req *http.Request) {
			if incoming == nil {
				return
			}
			for _, name := range cookies {
				if name != AccessCookieName {
					continue
				}
				if _, present := incoming.Header["Authorization"]; present {
					if token, source := accessTokenFromRequest(incoming); source == accessTokenFromBearer {
						req.Header.Set("Authorization", "Bearer "+token)
					}
					return
				}
				break
			}
			for _, name := range cookies {
				if cookie, err := incoming.Cookie(name); err == nil {
					req.AddCookie(cookie)
				}
			}
		})
	}
	if csrf {
		if token, ok := CSRFToken(incoming); ok {
			opts = append(opts, withCSRFToken(token))
		}
	}
	return opts
}

`)

	for _, method := range methods {
		b.WriteString(method)
		b.WriteByte('\n')
	}
	return b.Bytes(), nil
}

func (g generator) clientImports(ops []operation) string {
	imports := []string{"context", "net/http"}
	var externalImports []string
	if hasParameters(ops) {
		imports = append(imports, "net/url")
	}
	if g.needsParameterImport(ops, "strconv") {
		imports = append(imports, "strconv")
	}
	if g.needsParameterImport(ops, "strings") {
		imports = append(imports, "strings")
	}
	if g.needsParameterImport(ops, "time") {
		imports = append(imports, "time")
	}
	if g.needsParameterImport(ops, "github.com/google/uuid") {
		externalImports = append(externalImports, "github.com/google/uuid")
	}

	var b bytes.Buffer
	b.WriteString("import (\n")
	for _, path := range imports {
		b.WriteString(fmt.Sprintf("\t%q\n", path))
	}
	if len(externalImports) > 0 {
		b.WriteByte('\n')
		for _, path := range externalImports {
			b.WriteString(fmt.Sprintf("\t%q\n", path))
		}
	}
	b.WriteString(")\n\n")
	return b.String()
}

func hasParameters(ops []operation) bool {
	for _, op := range ops {
		if len(op.PathParams) > 0 || len(op.QueryParams) > 0 {
			return true
		}
	}
	return false
}

func (g generator) needsParameterImport(ops []operation, importPath string) bool {
	for _, op := range ops {
		for _, p := range append(append([]parameter{}, op.PathParams...), op.QueryParams...) {
			schemaType, schemaFormat := parameterSchemaType(p)
			switch importPath {
			case "strconv":
				if g.schemaNeedsImport(p.Schema, importPath) {
					return true
				}
				if schemaType == "" && scalarTypeNeedsImport(p.Type, importPath) {
					return true
				}
			case "strings":
				if parameterIsArray(p) && (p.In == "path" || queryArrayNeedsJoin(p)) {
					return true
				}
			case "time":
				if g.schemaNeedsImport(p.Schema, importPath) || schemaFormat == "date-time" || p.Type == "time.Time" {
					return true
				}
				if schemaType == "" && scalarTypeNeedsImport(p.Type, importPath) {
					return true
				}
			case "github.com/google/uuid":
				if g.schemaNeedsImport(p.Schema, importPath) || schemaFormat == "uuid" || p.Type == "uuid.UUID" {
					return true
				}
				if schemaType == "" && scalarTypeNeedsImport(p.Type, importPath) {
					return true
				}
			}
		}
	}
	return false
}

func scalarTypeNeedsImport(goType, importPath string) bool {
	goType = strings.TrimPrefix(goType, "[]")
	switch importPath {
	case "strconv":
		return goType == "bool" || goType == "int" || goType == "float64"
	case "time":
		return goType == "time.Time"
	case "github.com/google/uuid":
		return goType == "uuid.UUID"
	default:
		return false
	}
}

func (g generator) schemaNeedsImport(ref *openapi3.SchemaRef, importPath string) bool {
	if ref == nil || ref.Value == nil {
		return false
	}
	types := ref.Value.Type.Slice()
	if len(types) == 0 {
		return false
	}
	switch importPath {
	case "strconv":
		if types[0] == "boolean" || types[0] == "integer" || types[0] == "number" {
			return true
		}
	case "time":
		if ref.Value.Format == "date-time" {
			return true
		}
	case "github.com/google/uuid":
		if ref.Value.Format == "uuid" {
			return true
		}
	}
	return types[0] == "array" && g.schemaNeedsImport(ref.Value.Items, importPath)
}

func (g generator) method(op operation) (string, error) {
	var b bytes.Buffer
	name := "Call" + goName(op.OperationID)
	params := []string{"ctx context.Context"}
	if op.NeedsRequest {
		params = append(params, "incoming *http.Request")
	}
	for _, p := range op.PathParams {
		params = append(params, lowerName(p.Name)+" "+p.Type)
	}
	for _, p := range op.QueryParams {
		params = append(params, lowerName(p.Name)+" "+p.Type)
	}
	if op.RequestType != "" {
		params = append(params, "body "+op.RequestType)
	}

	resultType := "error"
	if op.ResponseType != "" {
		resultType = "(*" + op.ResponseType + ", error)"
	}
	b.WriteString(fmt.Sprintf("func (c *Client) %s(%s) %s {\n", name, strings.Join(params, ", "), resultType))
	if op.ResponseType != "" {
		b.WriteString("\tvar out " + op.ResponseType + "\n")
	}
	pathCode, err := g.pathCode(op)
	if err != nil {
		return "", err
	}
	b.WriteString(pathCode)
	if len(op.QueryParams) > 0 {
		b.WriteString("\tquery := url.Values{}\n")
		for i, p := range op.QueryParams {
			if err := g.writeQueryParameter(&b, p, i); err != nil {
				return "", err
			}
		}
		b.WriteString("\tpath += \"?\" + query.Encode()\n")
	}
	body := "nil"
	if op.RequestType != "" {
		body = "body"
	}
	out := "nil"
	if op.ResponseType != "" {
		out = "&out"
	}
	switch op.Auth {
	case authInternalBearer:
		b.WriteString(fmt.Sprintf("\terr := c.internalJSON(ctx, %s, path, %s, %s)\n", methodConst(op.Method), body, out))
	case authCookie:
		b.WriteString(fmt.Sprintf("\t_, err := c.doJSONBody(ctx, %s, path, %s, %s, apiRequestOptions(incoming, %#v, %t)...)\n", methodConst(op.Method), body, out, op.Cookies, op.NeedsCSRF))
	case authPublic:
		b.WriteString(fmt.Sprintf("\t_, err := c.doJSONBody(ctx, %s, path, %s, %s)\n", methodConst(op.Method), body, out))
	}
	b.WriteString("\tif err != nil {\n")
	if op.ResponseType != "" {
		b.WriteString("\t\treturn nil, err\n")
	} else {
		b.WriteString("\t\treturn err\n")
	}
	b.WriteString("\t}\n")
	if op.ResponseType != "" {
		b.WriteString("\treturn &out, nil\n")
	} else {
		b.WriteString("\treturn nil\n")
	}
	b.WriteString("}\n")
	return b.String(), nil
}
