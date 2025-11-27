import re
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
import operator
from functools import reduce

logger = logging.getLogger(__name__)

class QueryEngine:
    """Powerful log search and query engine"""
    
    def __init__(self, storage_backend):
        self.storage = storage_backend
        self.operators = {
            '==': operator.eq,
            '!=': operator.ne,
            '>': operator.gt,
            '>=': operator.ge,
            '<': operator.lt,
            '<=': operator.le,
            '=~': lambda x, y: bool(re.search(y, str(x))),
            '!~': lambda x, y: not bool(re.search(y, str(x))),
            'in': lambda x, y: str(x) in y,
            'not in': lambda x, y: str(x) not in y
        }
    
    def search(self, query: Dict[str, Any]) -> Dict[str, Any]:
        """Execute search query"""
        try:
            # Parse query
            parsed_query = self._parse_query(query)
            
            # Execute query
            results = self.storage.search(parsed_query)
            
            # Apply post-processing
            processed_results = self._process_results(results, query)
            
            return {
                'success': True,
                'results': processed_results,
                'total': len(processed_results),
                'query': parsed_query
            }
            
        except Exception as e:
            logger.error(f"Search error: {e}")
            return {
                'success': False,
                'error': str(e),
                'results': [],
                'total': 0
            }
    
    def _parse_query(self, query: Dict[str, Any]) -> Dict[str, Any]:
        """Parse search query into executable form"""
        parsed = {
            'filters': [],
            'time_range': {},
            'sort': [],
            'pagination': {},
            'fields': []
        }
        
        # Parse filters
        if 'filters' in query:
            parsed['filters'] = self._parse_filters(query['filters'])
        
        # Parse time range
        if 'time_range' in query:
            parsed['time_range'] = self._parse_time_range(query['time_range'])
        else:
            # Default time range: last 1 hour
            parsed['time_range'] = {
                'field': '@timestamp',
                'start': datetime.now() - timedelta(hours=1),
                'end': datetime.now()
            }
        
        # Parse sort
        if 'sort' in query:
            parsed['sort'] = self._parse_sort(query['sort'])
        else:
            # Default sort: newest first
            parsed['sort'] = [('@timestamp', 'desc')]
        
        # Parse pagination
        if 'pagination' in query:
            parsed['pagination'] = query['pagination']
        else:
            parsed['pagination'] = {
                'limit': 100,
                'offset': 0
            }
        
        # Parse fields
        if 'fields' in query:
            parsed['fields'] = query['fields']
        
        return parsed
    
    def _parse_filters(self, filters: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Parse filter conditions"""
        parsed_filters = []
        
        for filter_obj in filters:
            if 'field' in filter_obj and 'operator' in filter_obj and 'value' in filter_obj:
                parsed_filter = {
                    'field': filter_obj['field'],
                    'operator': filter_obj['operator'],
                    'value': filter_obj['value'],
                    'original': filter_obj
                }
                parsed_filters.append(parsed_filter)
            elif 'and' in filter_obj:
                # AND condition
                parsed_filters.append({
                    'type': 'and',
                    'conditions': self._parse_filters(filter_obj['and'])
                })
            elif 'or' in filter_obj:
                # OR condition
                parsed_filters.append({
                    'type': 'or', 
                    'conditions': self._parse_filters(filter_obj['or'])
                })
            elif 'not' in filter_obj:
                # NOT condition
                parsed_filters.append({
                    'type': 'not',
                    'condition': self._parse_filters([filter_obj['not']])[0]
                })
        
        return parsed_filters
    
    def _parse_time_range(self, time_range: Dict[str, Any]) -> Dict[str, Any]:
        """Parse time range specification"""
        parsed = {
            'field': time_range.get('field', '@timestamp')
        }
        
        # Parse relative time (e.g., "1h", "30m", "7d")
        if 'relative' in time_range:
            relative = time_range['relative']
            now = datetime.now()
            
            # Parse relative time string
            match = re.match(r'(\d+)([smhdw])', relative)
            if match:
                value, unit = match.groups()
                value = int(value)
                
                if unit == 's':
                    delta = timedelta(seconds=value)
                elif unit == 'm':
                    delta = timedelta(minutes=value)
                elif unit == 'h':
                    delta = timedelta(hours=value)
                elif unit == 'd':
                    delta = timedelta(days=value)
                elif unit == 'w':
                    delta = timedelta(weeks=value)
                
                parsed['start'] = now - delta
                parsed['end'] = now
        
        # Parse absolute time
        if 'start' in time_range:
            parsed['start'] = self._parse_datetime(time_range['start'])
        if 'end' in time_range:
            parsed['end'] = self._parse_datetime(time_range['end'])
        
        return parsed
    
    def _parse_datetime(self, dt_str: str) -> datetime:
        """Parse datetime string to datetime object"""
        try:
            # Try ISO format
            return datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
        except ValueError:
            # Try other common formats
            formats = [
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d"
            ]
            
            for fmt in formats:
                try:
                    return datetime.strptime(dt_str, fmt)
                except ValueError:
                    continue
            
            raise ValueError(f"Unable to parse datetime: {dt_str}")
    
    def _parse_sort(self, sort_spec: List[Dict[str, Any]]) -> List[tuple]:
        """Parse sort specification"""
        sort_list = []
        
        for sort_item in sort_spec:
            if isinstance(sort_item, dict):
                field = sort_item.get('field', '@timestamp')
                order = sort_item.get('order', 'desc')
                sort_list.append((field, order))
            elif isinstance(sort_item, str):
                # Simple string format: "field:order"
                if ':' in sort_item:
                    field, order = sort_item.split(':', 1)
                else:
                    field, order = sort_item, 'desc'
                sort_list.append((field, order))
        
        return sort_list
    
    def _process_results(self, results: List[Dict[str, Any]], query: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Process and transform search results"""
        processed = []
        
        for result in results:
            # Apply field selection
            if 'fields' in query and query['fields']:
                selected_result = {}
                for field in query['fields']:
                    if field in result:
                        selected_result[field] = result[field]
                processed.append(selected_result)
            else:
                processed.append(result)
        
        # Apply highlighting if requested
        if query.get('highlight'):
            processed = self._apply_highlighting(processed, query['highlight'])
        
        return processed
    
    def _apply_highlighting(self, results: List[Dict[str, Any]], highlight_config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Apply syntax highlighting to search results"""
        highlighted_results = []
        
        for result in results:
            highlighted = result.copy()
            
            # Highlight matching terms in specified fields
            highlight_fields = highlight_config.get('fields', ['message'])
            pre_tag = highlight_config.get('pre_tag', '<mark>')
            post_tag = highlight_config.get('post_tag', '</mark>')
            
            # Extract search terms from filters (simplified)
            search_terms = self._extract_search_terms(highlight_config.get('filters', []))
            
            for field in highlight_fields:
                if field in highlighted and search_terms:
                    field_value = str(highlighted[field])
                    for term in search_terms:
                        if term:  # Skip empty terms
                            pattern = re.compile(re.escape(term), re.IGNORECASE)
                            field_value = pattern.sub(
                                f"{pre_tag}{term}{post_tag}", 
                                field_value
                            )
                    highlighted[f'{field}_highlighted'] = field_value
            
            highlighted_results.append(highlighted)
        
        return highlighted_results
    
    def _extract_search_terms(self, filters: List[Dict[str, Any]]) -> List[str]:
        """Extract search terms from filters for highlighting"""
        terms = []
        
        for filter_obj in filters:
            if 'value' in filter_obj and isinstance(filter_obj['value'], str):
                terms.append(filter_obj['value'])
            elif 'conditions' in filter_obj:
                terms.extend(self._extract_search_terms(filter_obj['conditions']))
        
        return terms

class QueryLanguage:
    """Simple query language parser for log search"""
    
    @staticmethod
    def parse(query_string: str) -> Dict[str, Any]:
        """Parse query string into structured query"""
        try:
            # Simple query language syntax:
            # field:value field2:value2 "phrase search"
            # field=value field!=value field=~regex
            # time:1h time:2023-01-01,2023-01-02
            # sort:field:asc limit:100
            
            query = {
                'filters': [],
                'time_range': {},
                'sort': [],
                'pagination': {'limit': 100, 'offset': 0}
            }
            
            # Split into tokens while preserving quoted strings
            tokens = QueryLanguage._tokenize(query_string)
            
            for token in tokens:
                # Handle key:value pairs
                if ':' in token and not token.startswith('"'):
                    key, value = token.split(':', 1)
                    
                    if key == 'time':
                        query['time_range'] = QueryLanguage._parse_time_value(value)
                    elif key == 'sort':
                        field, order = value.split(':') if ':' in value else (value, 'desc')
                        query['sort'].append({'field': field, 'order': order})
                    elif key == 'limit':
                        query['pagination']['limit'] = int(value)
                    elif key == 'offset':
                        query['pagination']['offset'] = int(value)
                    else:
                        # Field filter
                        operator = '=~' if value.startswith('/') and value.endswith('/') else '=='
                        filter_value = value[1:-1] if operator == '=~' else value
                        
                        query['filters'].append({
                            'field': key,
                            'operator': operator,
                            'value': filter_value
                        })
                
                # Handle quoted phrases (full text search)
                elif token.startswith('"') and token.endswith('"'):
                    phrase = token[1:-1]
                    query['filters'].append({
                        'field': 'message',
                        'operator': '=~',
                        'value': re.escape(phrase)
                    })
                
                # Handle standalone terms (full text search)
                elif not any(c in token for c in ':=!<>~'):
                    query['filters'].append({
                        'field': 'message', 
                        'operator': '=~',
                        'value': re.escape(token)
                    })
            
            return query
            
        except Exception as e:
            logger.error(f"Error parsing query string: {e}")
            return {'filters': [], 'time_range': {}, 'sort': [], 'pagination': {'limit': 100, 'offset': 0}}
    
    @staticmethod
    def _tokenize(query_string: str) -> List[str]:
        """Tokenize query string while preserving quoted strings"""
        tokens = []
        current_token = ""
        in_quotes = False
        quote_char = None
        
        for char in query_string:
            if char in ['"', "'"] and not in_quotes:
                in_quotes = True
                quote_char = char
                current_token += char
            elif char == quote_char and in_quotes:
                in_quotes = False
                current_token += char
                tokens.append(current_token)
                current_token = ""
            elif char == ' ' and not in_quotes:
                if current_token:
                    tokens.append(current_token)
                    current_token = ""
            else:
                current_token += char
        
        if current_token:
            tokens.append(current_token)
        
        return tokens
    
    @staticmethod
    def _parse_time_value(time_value: str) -> Dict[str, Any]:
        """Parse time value specification"""
        # Relative time: 1h, 30m, 7d
        if re.match(r'^\d+[smhdw]$', time_value):
            return {'relative': time_value}
        
        # Absolute time range: start,end
        elif ',' in time_value:
            start, end = time_value.split(',', 1)
            return {'start': start, 'end': end}
        
        # Absolute time point
        else:
            return {'start': time_value, 'end': datetime.now().isoformat()}
