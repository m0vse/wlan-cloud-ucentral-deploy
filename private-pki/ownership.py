"""Resolve authoritative provisioning ownership without inferring approval."""
import re


def identifier(value, empty=False):
    if empty and value == '':
        return value
    if not isinstance(value, str) or not re.fullmatch('[A-Za-z0-9_-]{1,128}', value):
        raise ValueError('Invalid authoritative owner identifier')
    return value


def snapshot(controller, inventory, authorization):
    if not isinstance(inventory, dict):
        raise ValueError('Authoritative inventory required')
    identity = identifier(inventory.get('id'))
    serial = inventory.get('serialNumber')
    if not isinstance(serial, str) or not re.fullmatch('[0-9a-f]{12}', serial):
        raise ValueError('Canonical inventory serial required')
    direct = {field: identifier(inventory.get(field), empty=True) for field in ('entity', 'venue', 'subscriber')}
    venues, entities = [], []
    visited = set()
    cursor = direct['venue']
    venue_entities = []
    while cursor:
        if cursor in visited or len(venues) >= 32:
            raise ValueError('Ambiguous or cyclic venue ancestry')
        visited.add(cursor)
        venue = controller.fetch(16005, f'venue/{cursor}', authorization)
        if venue.get('id') != cursor:
            raise ValueError('Venue identity mismatch')
        parent, entity = identifier(venue.get('parent'), True), identifier(venue.get('entity'), True)
        venues.append({'id': cursor, 'parent': parent, 'entity': entity})
        if entity:
            venue_entities.append(entity)
        cursor = parent
    # Venue ancestry is followed first by OWPROV; an inherited entity is valid.
    effective = venue_entities[-1] if venue_entities else direct['entity']
    if direct['entity'] and effective and direct['entity'] != effective:
        raise ValueError('Conflicting direct and inherited entity ownership')
    if any(value != effective for value in venue_entities):
        raise ValueError('Conflicting venue ancestry ownership')
    visited = set()
    cursor = effective
    while cursor:
        if cursor in visited or len(entities) >= 32:
            raise ValueError('Ambiguous or cyclic entity ancestry')
        visited.add(cursor)
        entity = controller.fetch(16005, f'entity/{cursor}', authorization)
        if entity.get('id') != cursor:
            raise ValueError('Entity identity mismatch')
        parent = identifier(entity.get('parent'), True)
        # Preserve entity links even though parent controls inheritance.
        linked = identifier(entity.get('entity', ''), True)
        entities.append({'id': cursor, 'parent': parent, 'entity': linked})
        cursor = parent
    subscriber = None
    if direct['subscriber']:
        user = controller.fetch(16001, f'subuser/{direct["subscriber"]}', authorization)
        if user.get('id') != direct['subscriber'] or user.get('userRole') != 'subscriber' or type(user.get('suspended')) is not bool or type(user.get('blackListed')) is not bool or user['suspended'] or user['blackListed']:
            raise ValueError('Subscriber identity or status refused')
        owner = identifier(user.get('owner'))
        # The subscriber's recorded owner must exist too, and be active.
        operator = controller.fetch(16001, f'user/{owner}', authorization)
        if operator.get('id') != owner or type(operator.get('suspended')) is not bool or type(operator.get('blackListed')) is not bool or operator['suspended'] or operator['blackListed']:
            raise ValueError('Subscriber owner refused')
        subscriber = {'id': user['id'], 'owner': owner, 'suspended': False, 'blackListed': False}
    if not effective and subscriber is None:
        raise ValueError('Explicit reviewed ownership required')
    return {'inventoryId': identity, 'serial': serial, 'direct': direct,
            'venueAncestry': venues, 'entityAncestry': entities,
            'effectiveEntity': effective, 'subscriber': subscriber}
